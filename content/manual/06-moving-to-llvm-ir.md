---
title: "Moving to LLVM IR"
weight: 6
summary: "From IGNIL to optimizable LLVM IR"
---

IGNIL (chapter 5) is architecture-independent, but it's still a bespoke IR
with a small, fixed opcode set — there's no optimizer for it. `LLVMLifter`
closes that gap: it translates a `Function`'s IGNIL blocks into real LLVM
IR, so you get everything LLVM's optimization pipeline already knows how to
do — constant folding, dead code elimination, SSA construction — applied to
lifted machine code.

## The `LLVMLifter` class

{{< compare >}}
{{< pane lang="cpp" slot="first" >}}
#include <dragon/lifters/llvm/LLVMLifter.hpp>

dragon::llvmlifter::LLVMLifter lifter{dragon::Architecture::ARM64, "foo_module"};

bool ok = lifter.lift(function, graph);   // function's blocks must all have IGNIL translations
if (ok)
    std::cout << lifter.ir();             // textual LLVM IR
{{< /pane >}}
{{< pane lang="python" slot="second" >}}
lifter = dragon.LLVMLifter(dragon.Architecture.ARM64, "foo_module")
ok = lifter.lift(fn, graph)
print(lifter.ir())
{{< /pane >}}
{{< /compare >}}

`lift()` returns `false` if any block reachable from the function is
missing an IGNIL translation — the lifter refuses to produce a function
with a gap in it rather than silently emitting wrong code.

> **Create one `LLVMLifter` per function.** Each instance owns a single
> `llvm::Module`; the intended pattern (and the one every example in
> `examples/cpp/llvmir_lifting.cpp` follows) is one `LLVMLifter` per lifted
> function, read its `ir()`, and move on. Calling `lift()` a second time on
> the *same* `LLVMLifter` instance — even re-lifting the same function —
> was tested while writing this manual and segfaults. Don't do it; construct
> a fresh `LLVMLifter` per function instead.

## The calling convention

Every lifted function has the signature `void @sub_<address>(ptr %mem, ptr %regs)`
(the name is the function's start address in **decimal**, not hex — `foo`
at `0x1000` becomes `@sub_4096`). Two opaque pointers carry all lifted
state:

- **`%regs`** — the same flat register address space from chapter 5's
  `Reg{offset, width}` values. Reading `X0`/`W0` at the start of the
  function is a `getelementptr` on `%regs` at offset 0, exactly matching
  `dragon::arm::X0`'s offset.
- **`%mem`** — the address space `LOAD`/`STORE` IGNIL ops read and write
  through, via `getelementptr` + `load`/`store` at the computed address.

Only registers the function *actually touches* get an `alloca` — the
lifter's first pass (`buildRegFile`) scans every IGNIL op in every block
and allocates one `alloca` per `(offset, width)` pair actually referenced,
not one for every architectural register.

## Optimization passes

`LLVMLifter` bundles four passes, meant to run in this order (or all at
once via `optimize()`/`run_mem2reg()` + friends in Python):

| Pass | Effect |
|---|---|
| `runMem2Reg()` | Promotes the register-file `alloca`s to SSA values, inserting `phi` nodes at block merges. This is what turns "read/write a stack slot" into real dataflow. |
| `runInstCombine()` | Folds arithmetic/comparison patterns — notably the mask/OR sequences IGNIL's sub-register handling produces. |
| `runGVN()` | Eliminates redundant loads (global value numbering) — e.g. re-reading `%mem[SP]` twice in a row collapses to one load. |
| `runDCE()` | Removes now-dead computations — very relevant here, since IGNIL always computes *all four* condition flags per comparison (chapter 5), and DCE deletes the ones the function never actually branches on. |

## Watching it optimize: the running example

Lifting the same ARM64 `foo(x)` function from chapters 3-5 and printing
`ir()` before and after `optimize()`:

```python
fn = graph.get_function(0x1000)
lifter = dragon.LLVMLifter(dragon.Architecture.ARM64, "foo_module")
lifter.lift(fn, graph)

print(lifter.ir())      # non-optimized
lifter.optimize()
print(lifter.ir())      # optimized
```

**Non-optimized** — a near-literal transcription of chapter 5's IGNIL, one
`alloca` per touched register, explicit loads/stores for every access:

```text
define void @sub_1000(ptr %mem, ptr %regs) {
bb_4096:
  %W0 = alloca i32, align 4
  %FP = alloca i64, align 8
  %LR = alloca i64, align 8
  %SP = alloca i64, align 8
  %NF = alloca i8, align 1
  %ZF = alloca i8, align 1
  %CF = alloca i8, align 1
  %VF = alloca i8, align 1
  %0 = getelementptr i8, ptr %regs, i32 0
  %1 = load i32, ptr %0, align 4
  store i32 %1, ptr %W0, align 4
  ; ... FP/LR/SP/NF/ZF/CF/VF loaded from %regs the same way ...
  %16 = load i64, ptr %SP, align 4
  %17 = add i64 %16, -16
  %18 = getelementptr i8, ptr %mem, i64 %17
  %19 = load i64, ptr %FP, align 4
  store i64 %19, ptr %18, align 4          ; stp x29,x30,[sp,#-16]! (first store)
  %20 = add i64 %17, 8
  %21 = getelementptr i8, ptr %mem, i64 %20
  %22 = load i64, ptr %LR, align 4
  store i64 %22, ptr %21, align 4          ; (second store)
  store i64 %17, ptr %SP, align 4
  %23 = load i64, ptr %SP, align 4
  %24 = add i64 %23, 0
  store i64 %24, ptr %FP, align 4          ; mov x29, sp
  %25 = load i32, ptr %W0, align 4
  %26 = sub i32 %25, 0                     ; cmp w0, #0
  %27 = icmp slt i32 %26, 0
  %28 = zext i1 %27 to i8
  store i8 %28, ptr %NF, align 1
  %29 = icmp eq i32 %26, 0
  %30 = zext i1 %29 to i8
  store i8 %30, ptr %ZF, align 1
  ; ... CF, VF computed and stored the same way ...
  %41 = load i8, ptr %ZF, align 1
  %42 = icmp ne i8 %41, 0
  %43 = load i8, ptr %NF, align 1
  %44 = load i8, ptr %VF, align 1
  %45 = icmp ne i8 %43, %44
  %46 = or i1 %42, %45                     ; Z==1 || N!=V  (the LE condition)
  br i1 %46, label %bb_4120, label %bb_4112

bb_4112:                                   ; preds = %bb_4096   (fallthrough: mov w0,#1 / b end_branch)
  store i32 1, ptr %W0, align 4
  br label %bb_4124

bb_4120:                                   ; preds = %bb_4096   (else_branch: mov w0,#-1)
  store i32 -1, ptr %W0, align 4
  br label %bb_4124

bb_4124:                                   ; preds = %bb_4120, %bb_4112   (end_branch)
  ; ldp x29,x30,[sp],#16 : two loads mirroring the stp above, then SP advances
  ; ... then every register written back to %regs before `ret void`
  ret void
}
```

**Optimized** (`mem2reg` → `instcombine` → `GVN` → `DCE`) — the `alloca`s
are gone, replaced by SSA values and a `phi`, and DCE has pruned every
flag computation the function doesn't actually use:

```text
define void @sub_1000(ptr %mem, ptr %regs) {
bb_4096:
  %0 = load i32, ptr %regs, align 4
  %1 = getelementptr i8, ptr %regs, i64 232
  %2 = load i64, ptr %1, align 4
  %3 = getelementptr i8, ptr %regs, i64 240
  %4 = load i64, ptr %3, align 4
  %5 = getelementptr i8, ptr %regs, i64 256
  %6 = load i64, ptr %5, align 4
  %7 = add i64 %6, -16
  %8 = getelementptr i8, ptr %mem, i64 %7
  store i64 %2, ptr %8, align 4
  %9 = getelementptr i8, ptr %mem, i64 %6
  %10 = getelementptr i8, ptr %9, i64 -8
  store i64 %4, ptr %10, align 4
  %11 = icmp slt i32 %0, 1
  br i1 %11, label %bb_4120, label %bb_4112

bb_4112:
  br label %bb_4124

bb_4120:
  br label %bb_4124

bb_4124:
  %W0.0 = phi i32 [ -1, %bb_4120 ], [ 1, %bb_4112 ]
  %12 = icmp eq i32 %0, 0
  %.lobit = lshr i32 %0, 31
  %13 = trunc nuw nsw i32 %.lobit to i8
  %14 = zext i1 %12 to i8
  store i32 %W0.0, ptr %regs, align 4
  store i64 %2, ptr %1, align 4
  store i64 %4, ptr %3, align 4
  store i64 %6, ptr %5, align 4
  %15 = getelementptr i8, ptr %regs, i64 784
  store i8 %13, ptr %15, align 1
  %16 = getelementptr i8, ptr %regs, i64 785
  store i8 %14, ptr %16, align 1
  %17 = getelementptr i8, ptr %regs, i64 786
  store i8 1, ptr %17, align 1
  %18 = getelementptr i8, ptr %regs, i64 787
  store i8 0, ptr %18, align 1
  ret void
}
```

This is the payoff of the whole pipeline: LLVM's optimizer, given no
information except the IGNIL translation of nine ARM64 instructions,
independently rediscovered that `foo(x)` is `x > 0 ? 1 : -1` and collapsed
the entire two-branch comparison down to one `icmp slt i32 %0, 1` feeding a
`phi`. It even worked out that, because the comparison is always against
`0`, `CF` and `VF` are *constant* on every path (`store i8 1`/`store i8 0`)
rather than needing to be computed — something visible nowhere in the
original assembly, only in the optimized IR.

## Working with the `llvm::Module` directly (C++ only)

`module()` exposes the underlying `llvm::Module&` for anything `ir()`
doesn't cover — running your own custom pass, JIT-compiling it with LLVM's
ORC APIs, or emitting object code:

```cpp
llvm::Module& mod = lifter.module();
// ... pass mod to your own llvm::PassBuilder pipeline, an ORC JIT, etc.
```

This is C++-only; the Python/C API only exposes the rendered IR text via
`ir()`.

## Scope

Same as chapter 5 — `LLVMLifter` consumes whatever `getIGNILBlock()` can
produce, so it inherits IGNIL's scope: x86 (32/64) and ARM64 only. A
`Function` with a block missing an IGNIL translation (ARM32, RISC-V, or a
gap from an unsupported addressing mode) makes `lift()` return `false`
rather than emit a function with a hole in it.
