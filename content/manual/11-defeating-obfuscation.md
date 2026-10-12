---
title: "Defeating Obfuscation"
weight: 11
summary: "Opaque predicates, junk code, MBA — and which dragon-tales engine collapses each"
---

Obfuscation keeps a program's behaviour and destroys its readability: a branch
that looks conditional but never varies, arithmetic disguised as bit-twiddling,
computation that exists only to waste your time. The taxonomy here follows
*Practical Reverse Engineering* (Dang, Gazet, Bachaalany), chapter 5 — opaque
predicates, junk/dead code, and arithmetic (mixed boolean-arithmetic)
transforms — plus a closing note on the virtualization case the companion
VMProtect analysis tackles.

dragon-tales brings two engines to this, and the whole skill is matching the
right one to the technique:

- **The LLVM optimizer** ([chapter 7](../07-moving-to-llvm-ir/)) rewrites
  lifted code toward canonical form and deletes computation nothing depends
  on. It is fast and it is *syntactic* — it folds what its rules recognize.
- **The symbolic executor** ([chapter 10](../10-symbolic-execution/)) proves
  *semantic* facts the optimizer's local rules can't reach: that a predicate
  is constant for every input, that two wildly different expressions are equal.

| Technique | Reach for | Why |
|---|---|---|
| Opaque predicate | symbolic executor | the dead edge is an algebraic fact, not a syntactic one |
| Junk / dead code | LLVM optimizer | DCE deletes computation no live value depends on |
| MBA arithmetic | symbolic executor | prove the obfuscated expression equals the simple one |
| Opaque constant | LLVM optimizer (+ solver to confirm) | constant-folding collapses it outright |

Every example below is x86-64, assembled with dragon-tales' own `Assembler`
([chapter 3](../03-assembling-your-code/)) so you can reproduce it without a
compiler, then disassembled and analyzed exactly as in chapters 4 and 7. The
outputs are real — produced by running each snippet against the library while
writing this chapter.

## Opaque predicates: a branch that can't be taken

An opaque predicate is a test whose outcome the obfuscator already knows but
the reader doesn't. A classic one rests on parity: `x * (x + 1)` is the product
of two consecutive integers, so it is *always even* — its low bit is always
zero. Branch on that low bit and one side is dead code that exists only to
inflate the CFG:

```nasm
    mov  rax, rdi          ; x
    lea  rcx, [rdi + 1]     ; x + 1
    imul rax, rcx           ; x * (x + 1)   -- always even
    and  rax, 1             ; low bit       -- always 0
    test rax, rax
    jne  taken              ; never taken
    xor  eax, eax           ; the real path: return 0
    ret
taken:
    mov  eax, 1             ; dead
    ret
```

A disassembler faithfully records both successors of the `jne` — it has no
way to know one is unreachable. The symbolic executor does: run the entry block
with `x` symbolic and ask which edges survive.

{{< compare >}}
{{< pane lang="cpp" slot="first" >}}
namespace x86 = dragon::x86;

ignil::SymbolicExecutor exec;
exec.symbolizeRegister(x86::RDI, "x");

ignil::RunResult r = exec.run(*graph.getIGNILBlock(0x1000));
for (const ignil::Successor &s : r.successors)
    std::cout << std::hex << s.address
              << (s.taken ? " (taken)\n" : " (not taken)\n");

// And the fact behind it: the low bit is zero for every x.
z3::expr rax = exec.readRegister(x86::RAX);
exec.proves((rax & exec.bv(1, 64)) == exec.bv(0, 64));   // true
{{< /pane >}}
{{< pane lang="python" slot="second" >}}
ex = dragon.SymbolicExecutor()
ex.symbolize_register(x86.RDI, 'x')

r = ex.run(graph.get_ignil_block(0x1000))
for s in r.successors:
    print(hex(s.address), '(taken)' if s.taken else '(not taken)')

# And the fact behind it: the low bit is zero for every x.
rax = ex.read_register(x86.RAX)
ex.proves((rax & ex.const(1, 64)) == ex.const(0, 64))    # True
{{< /pane >}}
{{< /compare >}}

```text
0x1018 (not taken)
proves low bit == 0: True
```

One successor, not two. The `0x101b` arm (`mov eax, 1`) is simply absent from
the reachable set, because the executor asked the solver whether the `jne` side
is satisfiable for *any* `x` and the answer was no. That single-element
successor list **is** the deobfuscation result: it tells you the edge to cut
and which path is real, so downstream analysis (or a trace lift of the
surviving path — the `liftBlock` note in [chapter 7](../07-moving-to-llvm-ir/))
works on the function that was actually there.

Notice which tool did it. Hand the same function to the LLVM optimizer and the
branch **survives** every pass:

```python
lifter = dragon.LLVMLifter(dragon.Architecture.X86_64, "opaque")
lifter.lift(graph.get_function(0x1000), graph)
lifter.optimize()                 # mem2reg → instcombine → GVN → DCE
# entry block still ends in:
#   br i1 %.not, label %bb_4120, label %bb_4123
```

`optimize()` cleans a great deal of flag noise, but it keeps both branches:
"`x*(x+1)` is even" is a number-theoretic fact, not a bit-pattern its
known-bits analysis tracks. This is the dividing line in one example — the
optimizer canonicalizes what it can see locally; the solver reasons about all
inputs. Opaque predicates live on the solver's side.

## Junk and dead code: computation that goes nowhere

The crudest padding is real instructions whose results are never used.
Here an expensive multiply writes `rax`, and the very next instruction
overwrites `rax` with the genuine result:

```nasm
    mov  rax, rdi
    imul rax, rsi      ; junk: product, immediately discarded
    mov  rax, rdi      ; overwrite -- the imul was dead
    add  rax, rsi      ; the real result: x + y
    ret
```

This one is the optimizer's job, and it needs no help. Lifting promotes the
register file to SSA (`mem2reg`), after which the multiply has no reader and
DCE deletes it:

{{< compare >}}
{{< pane lang="cpp" slot="first" >}}
dragon::llvmlifter::LLVMLifter lifter(dragon::Architecture::X86_64, "junk");
lifter.lift(fn, graph);

lifter.runMem2Reg();     // register file -> SSA
lifter.runInstCombine();
lifter.runGVN();
lifter.runDCE();         // the dead imul has no reader -> gone

std::cout << lifter.ir();
{{< /pane >}}
{{< pane lang="python" slot="second" >}}
lifter = dragon.LLVMLifter(dragon.Architecture.X86_64, "junk")
lifter.lift(fn, graph)

lifter.optimize()        # mem2reg -> instcombine -> GVN -> DCE
print(lifter.ir())
{{< /pane >}}
{{< /compare >}}

The raw lift contains the multiply; after optimization it is gone entirely —
the function body reduces to the one add that matters (`%regs+56` is `RDI`,
`%regs+48` is `RSI`):

```text
raw IR:         mul count = 1
optimized IR:   mul count = 0

bb_4096:
  %1 = load i64, ptr %0, align 4        ; RDI  (%regs + 56)
  %3 = load i64, ptr %2, align 4        ; RSI  (%regs + 48)
  %4 = add  i64 %3, %1                   ; x + y   -- the only arithmetic left
  store i64 %4, ptr %regs, align 4       ; -> RAX
  ...flag write-backs...
```

One caveat worth internalizing about this model: the lifter treats **every
register as live on exit** (a caller might read any of them), so register
write-backs and the condition-flag stores at the end are preserved even when
*this* function never reads them again. DCE removes computation whose result
reaches no stored value — like the overwritten `imul` above. Junk that an
obfuscator leaves sitting in a live register until `ret` is, by this
definition, not dead, and the optimizer keeps it. When you need to strip that
too, narrow what counts as live-out (the symbolic executor's `liveOut` set,
and [chapter 8](../08-loading-real-binaries/)'s argument/return recovery, are
how you establish which registers actually carry the result).

## Mixed boolean-arithmetic: addition wearing a disguise

MBA rewrites a simple operation as an equivalent tangle of `and`/`or`/`xor`
and shifts. The canonical identity is addition:

$$x + y \;=\; (x \oplus y) + 2\,(x \wedge y)$$

(the XOR is the sum without carries; `x & y` is exactly the carry positions,
doubled to carry them left). In assembly it reads as bit manipulation with no
`add`-of-the-operands in sight:

```nasm
    mov rax, rdi
    xor rax, rsi       ; x ^ y
    mov rcx, rdi
    and rcx, rsi
    shl rcx, 1          ; 2 * (x & y)
    add rax, rcx        ; (x ^ y) + 2*(x & y)
    ret
```

The optimizer does **not** fold this — instcombine has no rewrite for this
identity, so the optimized IR still shows the `xor`, `and`, `shl`, `add`
verbatim. The solver, which reasons about values rather than patterns, sees
straight through it:

{{< compare >}}
{{< pane lang="cpp" slot="first" >}}
ignil::SymbolicExecutor exec;
z3::expr x = exec.symbolizeRegister(x86::RDI, "x");
z3::expr y = exec.symbolizeRegister(x86::RSI, "y");

exec.run(*graph.getIGNILBlock(0x1000));
z3::expr rax = exec.readRegister(x86::RAX);

exec.proves(rax == x + y);    // true  -- it's just addition
exec.proves(rax == (x ^ y));  // false -- not the XOR alone
{{< /pane >}}
{{< pane lang="python" slot="second" >}}
ex = dragon.SymbolicExecutor()
x = ex.symbolize_register(x86.RDI, 'x')
y = ex.symbolize_register(x86.RSI, 'y')

ex.run(graph.get_ignil_block(0x1000))
rax = ex.read_register(x86.RAX)

ex.proves(rax == x + y)       # True  -- it's just addition
ex.proves(rax == (x ^ y))    # False -- not the XOR alone
{{< /pane >}}
{{< /compare >}}

```text
proves RAX == x + y : True
proves RAX == x ^ y : False
```

`proves(rax == x + y)` returning `True` is the recovery: the block, whatever it
looks like, computes `x + y` for every input. You supply the hypothesis — this
is the same `proves()` [chapter 10](../10-symbolic-execution/) used to confirm
"obfuscated arithmetic is really just `a + b`" — and the solver confirms or
refutes it with no guessing (a solver timeout comes back as `None`/`nullopt`,
never a false *True*).

## Opaque constants: arithmetic that's secretly a constant

Sometimes a pile of operations on a variable collapses to a value that doesn't
depend on the variable at all. `(x | 0) ^ x` is zero for every `x`, so masking
it yields a constant:

```nasm
    mov rax, rdi
    or  rax, 0          ; x | 0  == x
    xor rax, rdi        ; x ^ x  == 0
    and rax, 0xff        ; 0 & 0xff == 0
    ret
```

This is the case where the optimizer alone finishes the job: `or x, 0` → `x`,
`x ^ x` → `0`, `0 & 0xff` → `0`, all standard instcombine folds, so the entire
chain reduces to storing a constant:

```python
lifter.optimize()
# the whole computation collapses to:
#   store i64 0, ptr %regs, align 4      ; RAX = 0
```

and the solver agrees, which is how you'd confirm it on a form instcombine
*didn't* happen to fold:

```python
ex.run(graph.get_ignil_block(0x1000))
rax = ex.read_register(x86.RAX)
ex.evaluate(rax)              # 0   -- forced to exactly one value
ex.proves(rax == ex.const(0, 64))   # True
```

`evaluate()` is the question "does this expression have exactly one possible
value?" — the precise tool for an opaque constant. A non-constant expression
returns `None`; a constant returns the value.

## The heavyweight case: virtualization

Control-flow flattening and full virtualization (a bytecode VM with a dispatch
loop, as in the VMProtect target of [chapter 8](../08-loading-real-binaries/))
are where every technique above appears at once, wrapped around an interpreter.
No single pass defeats them; the pieces this manual already gave you are the
pieces you combine:

- the **loader** (chapter 8) to get at the protected image's real sections;
- **computed-jump resolution** ([chapter 10](../10-symbolic-execution/)) to turn
  the dispatcher's `jmp [table + opcode*8]` into the concrete handler set — the
  edge a flat CFG reconstructor can't recover;
- **symbolic execution** to extract each handler's effect (exactly the
  `proves()`/`evaluate()` reasoning above, one handler at a time);
- the **LLVM optimizer** to clean the recovered per-handler code and the
  stitched-together devirtualized function.

That end-to-end recovery is the subject of the companion VMProtect write-up
rather than this manual — but nothing in it is a new primitive. It is opaque
predicates, dead code, MBA and computed jumps, met with the same two engines,
at scale.

## The takeaway

Reach for the **optimizer first**: it is cheap, and it clears junk code,
opaque constants and the flag noise lifting always produces, leaving far less
to reason about. Then reach for the **solver** for the facts the optimizer
can't see locally — whether a predicate is opaque, whether two expressions are
equal, whether a value is secretly constant. Obfuscation is designed to defeat
the reader; it is not, in general, designed to defeat a theorem prover that
doesn't care what the code looks like.
