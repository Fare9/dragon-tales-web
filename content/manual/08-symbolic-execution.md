---
title: "Symbolic Execution with Z3"
weight: 8
summary: "solving for inputs, pruning dead branches, and resolving computed jumps"
---

Chapters 5 and 6 turned machine code into forms you can *read* — IGNIL, then
LLVM IR. This chapter is about the questions reading doesn't answer:

- What input makes this check pass?
- Is this branch a real branch, or is one side dead?
- This `jmp rax` — where can it actually go?

All three have the same shape: you know what the code *does* to its inputs,
and you want the solver to work backwards. `SymbolicExecutor` runs IGNIL over
Z3 bitvectors so you can ask.

> Requires a build with `-DDRAGON_USE_Z3=ON` (the default). Header:
> `<dragon/lifters/ignil/SymbolicExecutor.hpp>`.

## The idea: run the block without knowing its inputs

Chapter 5's IGNIL is already an interpreter's instruction set — `ADD`,
`LOAD`, `CJMP` and so on, with every value a `Const`, `Reg` or `Temp`. A
concrete interpreter would give each register a number and step through. A
*symbolic* one gives some of them a **variable** instead, and each op builds
an expression rather than computing a result.

Run `xor rax, rdi; add rax, rsi` with `RAX = 0` and `RDI`/`RSI` symbolic, and
`RAX` ends up holding the expression `(0 ^ a) + b`. That is not yet an
answer — but it is something a solver can be asked about.

## Setting up a machine

Two things to seed, in whatever mix the question needs:

| | concrete | symbolic |
|---|---|---|
| register | `setRegister(x86::RDI, 0x4000)` | `symbolizeRegister(x86::RDI, "a")` |
| memory | `mapMemory(0x6000, bytes)` | `symbolizeMemory(0x4000, 8, "flag")` |

Anything you don't seed is not an error: an untouched register or address
reads back as a fresh free variable, so a block always runs even when you
know nothing about its inputs. (Pass `symbolizeUnmappedReads = false` if you
would rather an unseeded location read as zero — useful when a block is meant
to run against a fully specified machine and a gap means you set it up
wrong.)

Registers are the same descriptors chapter 5 introduced — `dragon::x86::RDI`,
`dragon::arm::X0`. Nothing in the executor is architecture-specific; it only
ever sees `Reg` offsets, so an ARM64 block runs through the same code.

## What does this block compute?

Take the smallest possible example — three instructions, disassembled and
lifted exactly as in chapters 3–5:

```
0x1000: 48 31 F8   xor rax, rdi
0x1003: 48 01 F0   add rax, rsi
0x1006: c3         ret
```

{{< compare >}}
{{< pane lang="cpp" slot="first" >}}
#include <dragon/lifters/ignil/SymbolicExecutor.hpp>
#include <dragon/lifters/ignil/x86/x86IGNILRegs.hpp>

namespace ignil = dragon::ignil;
namespace x86   = dragon::x86;

ignil::SymbolicExecutor exec;
exec.setRegister(x86::RAX, 0);
z3::expr a = exec.symbolizeRegister(x86::RDI, "a");
z3::expr b = exec.symbolizeRegister(x86::RSI, "b");

exec.run(*graph.getIGNILBlock(0x1000));

z3::expr rax = exec.readRegister(x86::RAX);
exec.proves(rax == a + b);        // std::optional<bool> -> true
exec.proves(rax == a * b);        // -> false

// Pin one argument down and the other becomes solvable.
exec.assume(b == exec.bv(0x37, 64));
auto solution = exec.solve(rax == exec.bv(0x1337, 64));
solution->value("a");             // 0x1300
{{< /pane >}}
{{< pane lang="python" slot="second" >}}
ex = dragon.SymbolicExecutor()
ex.set_register(x86.RAX, 0)
a = ex.symbolize_register(x86.RDI, 'a')
b = ex.symbolize_register(x86.RSI, 'b')

ex.run(graph.get_ignil_block(0x1000))

rax = ex.read_register(x86.RAX)
ex.proves(rax == a + b)           # True
ex.proves(rax == a * b)           # False

# Pin one argument down and the other becomes solvable.
ex.assume(b == ex.const(0x37, 64))
solution = ex.solve(rax == ex.const(0x1337, 64))
solution.value('a')               # 0x1300
{{< /pane >}}
{{< /compare >}}

The interesting part is what *isn't* in that snippet. The block lifts to **31
IGNIL ops**, not three — most of them the `CF`/`ZF`/`SF`/`OF` bookkeeping the
`add` implies (chapter 5 showed the same expansion). None of it gets in the
way, because you are not pattern-matching the ops; you are asking the solver
about a value:

```
RAX expr:      (bvadd (bvxor #x0000000000000000 a) b)
proves a + b:  True
proves a * b:  False
```

Three queries worth knowing:

- **`proves(cond)`** — does `cond` hold for *every* input? This is the one
  that answers "is this obfuscated arithmetic really just `a + b`".
- **`evaluate(expr)`** — the value of `expr` if the constraints force exactly
  one, else nothing. This answers "did that pile of arithmetic actually
  compute a constant?"
- **`solve(goal)`** — an assignment making `goal` true, or nothing at all.

Each returns "I don't know" as a distinct answer (`std::nullopt` / `None`)
when the solver times out. It is never a guess.

## Solving for an input

Here is a real one. Compile this with `clang -O1 -c`:

```c
unsigned int fnv4(const unsigned char *s, unsigned int seed) {
    unsigned int h = seed;
    h = (h ^ s[0]) * 0x01000193u;
    h = (h ^ s[1]) * 0x01000193u;
    h = (h ^ s[2]) * 0x01000193u;
    h = (h ^ s[3]) * 0x01000193u;
    return h;
}
```

and pull `.text` out with `objdump` the way chapter 7 does:

```
0f b6 07 31 f0 69 c0 93 01 00 01 0f b6 4f 01 31 c1 69 c1 93 01 00 01
0f b6 4f 02 31 c1 69 c1 93 01 00 01 0f b6 4f 03 31 c1 69 c1 93 01 00 01 c3
```

It lifts to a single straight-line block — the loads, the mixing, the flag
noise:

```
t0:i64 = COPY(RDI:i64)          ; @0x1000    movzbl (%rdi),%eax
t1:i8  = LOAD(t0:i64)           ; @0x1000
EAX:i32 = ZEXT(t1:i8)           ; @0x1000
t2:i32 = XOR(EAX:i32, ESI:i32)  ; @0x1003    xor %esi,%eax
EAX:i32 = COPY(t2:i32)          ; @0x1003
CF:i8  = COPY(0x0:i1)           ; @0x1003
PF:i8  = UNDEF()                ; @0x1003
AF:i8  = UNDEF()                ; @0x1003
...
```

There is no closed form to invert an FNV hash. So don't invert it — describe
it, and let the solver search:

{{< compare >}}
{{< pane lang="cpp" slot="first" >}}
constexpr std::uint64_t kBuffer = 0x4000;

ignil::SymbolicExecutor exec;
exec.setRegister(x86::RDI, kBuffer);       // s
exec.setRegister(x86::ESI, 0x811C9DC5);    // seed
exec.symbolizeMemory(kBuffer, 4, "input");

// Printable ASCII only - the challenge's unstated precondition.
for (int i = 0; i < 4; ++i) {
    z3::expr byte = exec.readMemory(kBuffer + i, 8);
    exec.assume(z3::uge(byte, exec.bv(0x21, 8)));
    exec.assume(z3::ule(byte, exec.bv(0x7E, 8)));
}

exec.run(*graph.getIGNILBlock(0x1000));

auto solution = exec.solve(exec.readRegister(x86::EAX) == exec.bv(target, 32));
std::vector<std::uint8_t> input = solution->bytes("input");
{{< /pane >}}
{{< pane lang="python" slot="second" >}}
BUFFER = 0x4000

ex = dragon.SymbolicExecutor()
ex.set_register(x86.RDI, BUFFER)           # s
ex.set_register(x86.ESI, 0x811C9DC5)       # seed
ex.symbolize_memory(BUFFER, 4, 'input')

# Printable ASCII only - the challenge's unstated precondition.
for i in range(4):
    byte = ex.read_memory(BUFFER + i, 8)
    ex.assume(byte.uge(ex.const(0x21, 8)))
    ex.assume(byte.ule(ex.const(0x7e, 8)))

ex.run(graph.get_ignil_block(0x1000))

solution = ex.solve(ex.read_register(x86.EAX) == ex.const(target, 32))
solution.bytes('input')                    # b'l33t'
{{< /pane >}}
{{< /compare >}}

```
target = 0x1b2d12af
recovered: b'l33t'
```

The four bytes came back because they were *constrained* to come back.
Without the printable-ASCII assumption there are many preimages and the
solver returns whichever it finds first:

```
no charset constraint -> b'\xb6\xeb\xb2i'
```

Both are correct answers to the question as asked. Narrowing the question is
your job, and `assume()` is how you do it — it is also where a real
engagement's knowledge goes: an input length, a magic prefix, a checksum
byte, a range recovered from a preceding bounds check.

> `Solution::bytes(region)` reads a symbolised region straight back as bytes.
> A region of N bytes creates N variables named `<region>[0]`..`<region>[N-1]`;
> `value("name")` gets at any one of them, and `values()` dumps the lot.

## Which edges of this branch are real?

Chapter 4 built the CFG from branch *targets*. The solver can tell you
something the CFG can't: whether an edge is reachable at all.

```
0x1000: 48 83 FF 0A   cmp rdi, 10
0x1004: 7C 03         jl 0x1009
0x1006: 48 FF C0      inc rax
0x1009: c3            ret
```

Running the entry block gives a `RunResult` whose `successors` are the
addresses control flow can reach, each with the condition that reaches it:

{{< compare >}}
{{< pane lang="cpp" slot="first" >}}
ignil::SymbolicExecutor exec;
z3::expr n = exec.symbolizeRegister(x86::RDI, "n");
// exec.assume(n > exec.bv(100, 64));   // for the second run

ignil::RunResult r = exec.run(*graph.getIGNILBlock(0x1000));
for (const ignil::Successor &s : r.successors)
    std::cout << std::hex << s.address
              << (s.taken ? " (taken)\n" : " (not taken)\n");
{{< /pane >}}
{{< pane lang="python" slot="second" >}}
ex = dragon.SymbolicExecutor()
n = ex.symbolize_register(x86.RDI, 'n')
# ex.assume(n > ex.const(100, 64))      # for the second run

r = ex.run(graph.get_ignil_block(0x1000))
for s in r.successors:
    print(hex(s.address), '(taken)' if s.taken else '(not taken)')
{{< /pane >}}
{{< /compare >}}

```
with RDI unknown:      -> 0x1009 (taken)   -> 0x1006 (not taken)
knowing RDI > 100:     -> 0x1006 (not taken)
```

Nothing pattern-matched the comparison. The executor asked the solver whether
each side of the `CJMP` condition is satisfiable under the accumulated
constraints, and the `jl` side simply isn't once `RDI > 100`.

That is also what makes an **opaque predicate** collapse. A branch on
`x * (x + 1) & 1` is always even, so one side is unsatisfiable for *every*
`x` — the executor reports one successor, with no idea that it was looking at
obfuscation.

## Where does this computed jump go?

The hardest case for chapter 4's CFG recovery is a jump through a table,
because the target isn't in the instruction. A bytecode VM's dispatcher is
the canonical shape: fetch an opcode byte, index a handler table, jump.

```
0x1000: 0F B6 37                movzx esi, byte ptr [rdi]
0x1003: FF 24 F5 00 60 00 00    jmp qword ptr [rsi*8 + 0x6000]
```

Map the table concretely, symbolise the opcode, and give the solver the range
check a well-formed program would have satisfied:

{{< compare >}}
{{< pane lang="cpp" slot="first" >}}
ignil::SymbolicExecutor exec;
exec.mapMemory(0x6000, handlerTable);   // three 8-byte entries
exec.setRegister(x86::RDI, 0x7000);     // the VM instruction pointer

// The range check a well-formed program would already have passed.
z3::expr opcode = exec.symbolizeMemory(0x7000, 1, "vm_opcode");
exec.assume(z3::ult(opcode, exec.bv(3, 8)));

ignil::RunResult r = exec.run(*graph.getIGNILBlock(0x1000));
for (const ignil::Successor &s : r.successors)
    std::cout << "handler at 0x" << std::hex << s.address << "\n";
{{< /pane >}}
{{< pane lang="python" slot="second" >}}
ex = dragon.SymbolicExecutor()
ex.map_memory(0x6000, handler_table)    # three 8-byte entries
ex.set_register(x86.RDI, 0x7000)        # the VM instruction pointer

# The range check a well-formed program would already have passed.
opcode = ex.symbolize_memory(0x7000, 1, 'vm_opcode')
ex.assume(opcode.ult(ex.const(3, 8)))

r = ex.run(graph.get_ignil_block(0x1000))
for s in r.successors:
    print('handler at', hex(s.address))
{{< /pane >}}
{{< /compare >}}

```
discovered 3 handlers (complete=True):
  -> 0xaa00
  -> 0xbb00
  -> 0xcc00
```

The executor resolved a symbolic *address* — it enumerated the values
`rsi*8 + 0x6000` can take, loaded each, and reported the targets. That is the
edge set a CFG reconstructor is missing on a virtualised binary, and it came
out without a single VM-specific rule.

## When it can't answer, it says so

Drop the range check and the opcode is unconstrained, so the target could be
anything:

```
successors=0, complete=False
warning @0x1003: load address has more than 64 possible values
                 (or the solver timed out); left unresolved
warning @0x1003: branch target has more than 256 possible values
                 (or the solver timed out); left unresolved
```

This is the property to lean on. **`complete()`** is true only when the run
succeeded *and* every address and branch target resolved exactly — so the
successor list really is the complete set of reachable addresses. When it is
false, `warnings` says what had to be left open. The executor will not invent
three plausible handlers to fill the gap, and it will not quietly drop a
store to an address it couldn't pin down.

The budgets are yours to raise (`maxAddressSolutions`, `maxBranchTargets`), as
is the per-query timeout.

## What it models

Worth knowing before you trust an answer:

- **Registers and memory are byte-granular.** That is what makes
  sub-register aliasing come out right with no per-architecture table: `EAX`
  writes bytes 0–3, `AH` writes byte 1, and a later `RAX` read concatenates
  bytes 0–7 whatever mix of widths produced them.
- **A 32-bit write clears the upper half** of its 64-bit parent — the
  x86-64 and AArch64 rule, and the reason the dispatcher above is bounded by
  the byte it fetched rather than by whatever was in `RSI` before.
- **Symbolic addresses are concretized**, not modelled with the theory of
  arrays: the executor enumerates the address's satisfying values and folds
  them into a select chain (a conditional update, for a store). Past the
  budget the access is reported unresolved.
- **Division follows Z3's total semantics** (`x/0` is all-ones unsigned).
  IGNIL leaves division by zero unspecified — constrain the divisor if it
  matters.
- **`CALL` does not model the callee.** Its target is reported as a
  successor; nothing else happens.
- **A block stops at its first terminator.** Set `stopAtTerminator = false`
  to run a *trace* from `liftTrace()`, whose interior terminators have to be
  stepped over rather than stopped at.

State persists across `run()` calls, so walking a path is a sequence of runs:
run a block, pick a successor, `assume()` its condition, run the next.

## Scope

The honest limits, beyond the modelling notes above:

- **One block at a time.** There is no loop handling and no automatic path
  exploration — `run()` executes a block, and following a path is something
  you drive. A loop has to be unrolled by running its body repeatedly, which
  means you need a bound on the trip count.
- **It inherits the lifter's scope.** Anything IGNIL can't express, the
  executor can't reason about. An `UNDEF` in the block (chapter 5) becomes a
  free variable, which is safe but uninformative — and [`ToDo/LifterGaps.md`](https://github.com/Fare9/dragon-tales/blob/main/ToDo/LifterGaps.md)
  tracks the forms that produce one.
- **Blocks come from lifting.** The C and Python APIs expose IGNIL blocks
  read-only, so from those layers you can symbolically execute code you
  disassembled, but not IR you built by hand. C++ can construct a `Block`
  directly.

[`examples/cpp/symbolic_execution.cpp`](https://github.com/Fare9/dragon-tales/blob/main/examples/cpp/symbolic_execution.cpp)
and [`examples/python/symbolic_execution.py`](https://github.com/Fare9/dragon-tales/blob/main/examples/python/symbolic_execution.py)
run every example in this chapter, plus a couple more.

