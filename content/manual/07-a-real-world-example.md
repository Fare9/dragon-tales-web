---
title: "A Real-World Example"
weight: 7
summary: "Compiling C, pulling .text with objdump, and running it through the whole pipeline"
---

Every previous chapter used bytes produced by dragon-tales' own `Assembler`
— clean, minimal, hand-written. Real binaries come from a compiler, and
compiler output is messier: prologues vary by optimization level, the
instruction selector reaches for encodings a hand-written example never
would, and — as this chapter shows directly rather than glossing over —
that's exactly where you find the edges of what a lifter currently
supports. This chapter compiles real C, extracts its `.text`, and runs it
through the full pipeline from chapters 3-6, including the rough edges.

## The source

A loop-based function — genuinely different from every earlier chapter's
straight-line/if-else example, since it produces a real CFG back-edge:

```c
int sum_to_n(int n) {
    volatile int total = 0;
    for (int i = 1; i <= n; i++) {
        total = total + i;
    }
    return total;
}
```

`volatile` is deliberate: without it, both GCC and Clang recognize this
loop as a closed-form arithmetic series at `-O1` and replace it with
Gauss's formula (`n*(n+1)/2`-shaped code) — defeating the point of showing
a loop at all. Marking `total` volatile forces every read/write to
actually happen, which keeps the loop intact.

## Compiling and extracting `.text`

```sh
gcc -O1 -fno-asynchronous-unwind-tables -fno-stack-protector -c sum.c -o sum.o
```

- **`-O1`**, not `-O0` or `-O2`. This matters more than it looks: `-O0`
  keeps every local variable on the stack and GCC/Clang's `-O0` codegen
  leans heavily on memory-destination instruction forms (`mov dword ptr
  [rbp-4], 0`, `add dword ptr [rbp-8], eax`, `cmp eax, dword ptr [rbp-20]`)
  that — verified empirically while writing this chapter — the current x86
  IGNIL lifter's opcode dispatch doesn't yet recognize (only the
  register-destination forms of `MOV`/`ADD`/`CMP` are wired up). At `-O0`
  those instructions are silently skipped — no `UNDEF`, no error, just a
  gap — which is worse than it sounds: a later instruction that depends on
  a skipped one (e.g. a `cmp` against memory feeding a conditional jump)
  ends up reading stale flag values. `-O2`, at the other extreme, unrolls
  and vectorizes even this small a loop into something too dense to be a
  good teaching example. `-O1` is the sweet spot for *this* function: real
  register-allocated code, still a genuine loop.
- **`-fno-asynchronous-unwind-tables -fno-stack-protector`** just keeps the
  output free of CFI directives and stack-canary instructions that would
  otherwise be visible in `objdump` but add nothing to the walkthrough.

```sh
llvm-objdump-21 -d --x86-asm-syntax=intel sum.o
```

```text
0000000000000000 <sum_to_n>:
       0: f3 0f 1e fa                  	endbr64
       4: c7 44 24 fc 00 00 00 00      	mov	dword ptr [rsp - 0x4], 0x0
       c: 85 ff                        	test	edi, edi
       e: 7e 21                        	jle	0x31 <sum_to_n+0x31>
      10: 83 c7 01                     	add	edi, 0x1
      13: b8 01 00 00 00               	mov	eax, 0x1
      18: 0f 1f 84 00 00 00 00 00      	nop	dword ptr [rax + rax]
      20: 8b 54 24 fc                  	mov	edx, dword ptr [rsp - 0x4]
      24: 01 c2                        	add	edx, eax
      26: 89 54 24 fc                  	mov	dword ptr [rsp - 0x4], edx
      2a: 83 c0 01                     	add	eax, 0x1
      2d: 39 f8                        	cmp	eax, edi
      2f: 75 ef                        	jne	0x20 <sum_to_n+0x20>
      31: 8b 44 24 fc                  	mov	eax, dword ptr [rsp - 0x4]
      35: c3                           	ret
```

> **Why `llvm-objdump`/`llvm-objcopy` and not GNU `objdump`/`objcopy`?**
> This isn't a style preference — on the machine this manual was written
> on, the system's GNU `binutils` build (`objdump --info`) only lists
> `i386`/`x86-64` BFD targets; pointing plain `objdump` at an AArch64
> object file below fails outright with `can't disassemble for
> architecture UNKNOWN!`, even though `readelf` correctly identifies it.
> `llvm-objdump`/`llvm-objcopy` come from the same LLVM 21 install
> dragon-tales itself links against, so they support every target LLVM
> does — which, conveniently, is a superset of every architecture
> dragon-tales supports. Use the LLVM tools for this kind of work and you
> won't hit target-support gaps your disassembler library doesn't also
> have.

Extract the raw section bytes — no ELF headers, no symbol table, just the
code:

```sh
llvm-objcopy-21 -O binary --only-section=.text sum.o sum.text
```

```python
with open("sum.text", "rb") as f:
    raw = f.read()
```

## Disassembling and analyzing it

```python
import dragon

cfg = dragon.Configuration(syntax=dragon.Syntax.INTEL)
disasm = dragon.Disassembler(dragon.Architecture.X86_64, cfg)
graph = disasm.analyze(raw, 0x0)   # base address 0 - it's a bare .text extract, not linked

fn = graph.get_function(0x0)
print("valid:", fn.is_valid, "blocks:", fn.num_blocks,
      "instructions:", fn.num_instructions, "cyclomatic:", fn.cyclomatic_complexity)
```

```text
valid: True blocks: 4 instructions: 15 cyclomatic: 1
```

Four blocks: the entry/init block, the loop body (block `0x20`, the one
with a predecessor from *within* the function — the actual back-edge), and
the early-exit/normal-exit tail at `0x31`. This is the first function in
the manual with a real loop-carried back-edge in its CFG — every earlier
chapter's example was if/else, straight-line control flow.

## The gap, in IGNIL

```python
for addr in graph.block_addresses():
    print(graph.get_ignil_block(addr).to_string())
```

The entry block (starting at `0x0`) is where the gap shows up. Compare the
disassembly above (`endbr64` at `0x0`, then `mov dword ptr [rsp-0x4], 0x0`
at `0x4`, then `test edi, edi` at `0xc`) against the actual IGNIL output:

```text
IGNILBlock @ 0x0
  t0:i32 = AND(EDI:i32, EDI:i32)  ; @0xc
  CF:i8 = COPY(0x0:i1)  ; @0xc
  PF:i8 = UNDEF()  ; @0xc
  AF:i8 = UNDEF()  ; @0xc
  t1:i1 = EQ(t0:i32, 0x0:i32)  ; @0xc
  ZF:i8 = COPY(t1:i1)  ; @0xc
  ...
```

**There is no op at all for the `mov dword ptr [rsp-0x4], 0x0` at `0x4`.**
It isn't lifted to `UNDEF` (which at least marks the destination as
unknown, the way `PF`/`AF` above honestly do for x86's rarely-modeled
parity/aux-carry flags) — it's simply absent, exactly the same "gap" chapter
3 warned about with `hasIndirectTarget`/unclassified instructions, except
here it's not an exotic edge case: **immediate-to-memory `mov` is one of
the single most common instruction forms in real x86 code**, and it isn't
in `X86IGNILLifter`'s opcode dispatch yet (only `MOV reg, reg/imm` and `MOV
reg, [mem]` / `MOV [mem], reg` are wired up — not `MOV [mem], imm`; the
same is true of `ADD [mem], reg/imm` and `CMP reg, [mem]`, though this
particular function doesn't happen to use those forms).

**The concrete consequence** shows up three chapters downstream, in the
optimized LLVM IR below: the early-return path (`n <= 0`) ends up reading
`total`'s stack slot via a `load` with **no corresponding `store` anywhere
before it** — because the `store` that should have initialized it to `0`
was the very instruction that got dropped. The IR stays structurally valid
(LLVM doesn't need every load to have a preceding store), but semantically,
lifting this function's `n <= 0` path currently returns garbage instead of
`0`. This is a real, present gap — not a hypothetical one — and it is
exactly the kind of thing to check for before trusting a lifted result:
look for a block whose IGNIL translation has noticeably fewer ops than the
disassembly listing above it has instructions.

## Through to LLVM IR anyway

The rest of the function — the actual loop — uses only register-form
`mov`/`add`/`cmp` and register+immediate-offset `load`/`store`, all of
which *are* supported, so it lifts and optimizes exactly like chapters 5-6
would predict:

```python
lifter = dragon.LLVMLifter(dragon.Architecture.X86_64, "sum_module")
lifter.lift(fn, graph)
# non-optimized: 228 lines, one alloca per touched register, explicit
# %regs loads for EAX/EDX/RSP/EDI/CF/PF/AF/ZF/SF/OF/DF up front, e.g.:
#   %EAX = alloca i32, align 4
#   ...
#   %0 = getelementptr i8, ptr %regs, i32 0
#   %1 = load i32, ptr %0, align 4
#   store i32 %1, ptr %EAX, align 4
#   ... (same pattern for every other touched register)

lifter.optimize()
print(lifter.ir())
```

```text
define void @sub_0(ptr %mem, ptr %regs) {
bb_0:
  %0 = getelementptr i8, ptr %regs, i64 16
  %1 = load i32, ptr %0, align 4
  %2 = getelementptr i8, ptr %regs, i64 32
  %3 = load i64, ptr %2, align 4
  %4 = getelementptr i8, ptr %regs, i64 56
  %5 = load i32, ptr %4, align 4
  %6 = icmp eq i32 %5, 0
  %.lobit = lshr i32 %5, 31
  %7 = trunc nuw nsw i32 %.lobit to i8
  %8 = icmp slt i32 %5, 1
  br i1 %8, label %bb_0.bb_49_crit_edge, label %bb_16

bb_0.bb_49_crit_edge:                             ; preds = %bb_0
  %.phi.trans.insert4 = getelementptr i8, ptr %mem, i64 %3
  %.phi.trans.insert5 = getelementptr i8, ptr %.phi.trans.insert4, i64 -4
  %.pre6 = load i32, ptr %.phi.trans.insert5, align 4   ; <-- the gap: no store ever targets this address
  br label %bb_49

bb_16:                                            ; preds = %bb_0
  %9 = add nuw i32 %5, 1
  %.phi.trans.insert = getelementptr i8, ptr %mem, i64 %3
  %.phi.trans.insert3 = getelementptr i8, ptr %.phi.trans.insert, i64 -4
  %.pre = load i32, ptr %.phi.trans.insert3, align 4
  br label %bb_32

bb_32:                                            ; preds = %bb_32, %bb_16
  %10 = phi i32 [ %.pre, %bb_16 ], [ %11, %bb_32 ]
  %EAX.0 = phi i32 [ 1, %bb_16 ], [ %12, %bb_32 ]
  %11 = add i32 %10, %EAX.0
  store i32 %11, ptr %.phi.trans.insert3, align 4
  %12 = add i32 %EAX.0, 1
  %13 = sub i32 %EAX.0, %5
  %14 = icmp ule i32 %12, %5
  %15 = zext i1 %14 to i8
  %16 = icmp eq i32 %EAX.0, %5
  %.lobit1 = lshr i32 %13, 31
  %17 = trunc nuw nsw i32 %.lobit1 to i8
  %18 = xor i32 %12, %9
  %19 = xor i32 %13, %12
  %20 = and i32 %18, %19
  %.lobit2 = lshr i32 %20, 31
  %21 = trunc nuw nsw i32 %.lobit2 to i8
  br i1 %16, label %bb_49, label %bb_32

bb_49:                                            ; preds = %bb_0.bb_49_crit_edge, %bb_32
  %22 = phi i32 [ %.pre6, %bb_0.bb_49_crit_edge ], [ %11, %bb_32 ]
  ; ... condition-flag phis, then every touched register written back to %regs ...
  store i32 %22, ptr %regs, align 4
  ret void
}
```

Despite the gap, this is a genuinely good result: `bb_32` is a real,
optimized loop with a `phi`-carried accumulator (`%EAX.0`) and induction
variable, GVN has proven the loop only needs to load `total`'s memory slot
once per iteration rather than on every access, and DCE has pruned every
flag computation the function doesn't branch on. The marked line is the one
place where the earlier gap surfaces — everything else here is a correct,
verified translation of real compiled code.

## Cross-compiling for ARM64

The same source, cross-compiled with `clang` (no separate ARM64 toolchain
needed — `clang`'s built-in target support handles it):

```sh
clang --target=aarch64-linux-gnu -O1 -c sum.c -o sum_arm64.o
llvm-objdump-21 -d sum_arm64.o
```

```text
0000000000000000 <sum_to_n>:
       0: d10043ff     	sub	sp, sp, #0x10
       4: 7100041f     	cmp	w0, #0x1
       8: b9000fff     	str	wzr, [sp, #0xc]
       c: 5400010b     	b.lt	0x2c <sum_to_n+0x2c>
      10: 52800028     	mov	w8, #0x1
      14: b9400fe9     	ldr	w9, [sp, #0xc]
      18: 71000400     	subs	w0, w0, #0x1
      1c: 0b090109     	add	w9, w8, w9
      20: 11000508     	add	w8, w8, #0x1
      24: b9000fe9     	str	w9, [sp, #0xc]
      28: 54ffff61     	b.ne	0x14 <sum_to_n+0x14>
      2c: b9400fe0     	ldr	w0, [sp, #0xc]
      30: 910043ff     	add	sp, sp, #0x10
      34: d65f03c0     	ret
```

Extract and disassemble it the same way — and here the *x86* gap doesn't
apply at all: `str wzr, [sp, #0xc]` (store the zero register to memory) is
a completely ordinary `STR` instruction to the ARM64 lifter, so `total`'s
initialization **is** captured correctly:

```python
disasm = dragon.Disassembler(dragon.Architecture.ARM64, cfg)
graph = disasm.analyze(raw_arm64, 0x0)
for addr in graph.block_addresses():
    print(graph.get_ignil_block(addr).to_string())
```

Every block lifts cleanly, zero `UNDEF`s, zero gaps — verified directly
while writing this chapter. But there's a second, different real-world
edge here: check `graph.function_addresses()` and it comes back **empty**.

```python
print(graph.function_addresses())   # []
```

The blocks and CFG are all there (`graph.block_addresses()` returns all
three), but nothing gets recognized as a *function*. Why: this is a leaf
function (it never calls anything), so at `-O1` Clang doesn't bother
establishing a stack frame — no `stp x29, x30, [sp, ...]!`, no `mov x29,
sp`. Chapter 5's ARM64 running example (`foo`, back in chapter 2) always
had exactly that prologue, because it was hand-written to include one.
dragon-tales' current ARM64 function-start heuristic looks for that
`stp`-based frame-establishment pattern specifically — a real, common ARM64
leaf function that omits it (which is the default at `-O1`+ for any
function that doesn't itself call out) won't be recognized as a function
start, which means `graph.get_function()` returns an invalid view and
`LLVMLifter.lift()` has nothing to lift.

**The practical takeaway:** `Instruction`/`BasicBlock`/IGNIL-level analysis
(chapters 3 and 5) works on this code just fine — it's only the
function-boundary/prologue heuristic (chapter 4) that misses it. If you're
exploring a real ARM64 binary and `function_addresses()` comes back sparse
or empty, don't assume the disassembly failed — check whether the
functions in question actually establish a frame; leaf functions and
tail-call-heavy code frequently don't. For a from-scratch ARM64 function
that *does* get recognized end-to-end (including the LLVM IR step), the
`foo(x)` example running through chapters 2-6 is the reference — the
difference between it and this one is exactly that hand-written prologue.

## Where to go from here

That is the pipeline end to end. Chapter 8 goes a step further and asks the
code questions reading it can't answer — what input satisfies this check,
which branches are real, where a computed jump goes. For topics beyond that,
see [IDEAS.md](https://github.com/Fare9/dragon-tales/blob/main/docs/manual/IDEAS.md)
(RISC-V once it has lifter support, writing a custom analysis pass). If
you run into a gap like the two in this chapter on your own code, that's
not a dead end: both are scope limitations of the current lifter/analysis,
not fundamental — the IGNIL opcode set and the `Graph`/`BasicBlock`/`Function`
model in chapters 4-5 have everything needed to describe the missing
cases; they just need a dispatch entry or a heuristic extended.
