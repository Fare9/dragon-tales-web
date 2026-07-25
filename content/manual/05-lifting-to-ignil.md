---
title: "Lifting to IGNIL"
weight: 5
summary: "dragon-tales' architecture-independent IL"
---

Everything up to this point has been architecture-specific: `Instruction`,
`BasicBlock`, `Function` all describe *this particular* x86-64 or ARM64
code. **IGNIL** (dragon-tales' intermediate language) is where that stops —
it's a small, architecture-independent instruction set that every lifted
block gets translated into, so downstream analysis (the backward slicer,
chapter 6's LLVM lifter) doesn't need to know anything about the source
architecture at all.

## The model

IGNIL has three concepts: **values**, **ops**, and **blocks**.

### Values — `Const`, `Reg`, `Temp`

```cpp
using Value = std::variant<Const, Reg, Temp>;
```

- **`Const{value, width}`** — an integer constant of a given bit width. Signedness isn't part of the value; it's decided by which opcode consumes it (`SLT` vs `ULT`, etc).
- **`Reg{offset, width, name}`** — an architectural register, modeled as a location in a flat **register address space**, not a symbolic name. Sub-registers share a base offset at different widths — on x86, `RAX` is `Reg{0, 64}`, `EAX` is `Reg{0, 32}`, `AL` is `Reg{0, 8}`, `AH` is `Reg{1, 8}` (byte 1 of RAX). This is what lets the lifter and the backward slicer reason about partial-register writes uniformly across architectures.
- **`Temp{id, width}`** — an SSA-style temporary. Every intermediate result of a multi-op translation gets a fresh temp; temps are never reassigned.

### Ops — one `Opcode` + optional dst + srcs

```cpp
struct Op {
  Opcode opcode;
  std::optional<Value> dst;   // absent for STORE, JMP, CJMP, CALL, RET
  std::vector<Value> srcs;
  std::uint64_t address{};    // the machine instruction this Op came from
};
```

One machine instruction lifts to **one or more** `Op`s — a single `cmp`
might expand into half a dozen IGNIL ops to compute all four condition
flags. `address` ties each op back to the instruction that produced it,
which is exactly how `ignil_lifting.cpp` (and the printer below) lines up
disassembly with IGNIL side by side.

The opcode set, grouped:

| Group | Opcodes |
|---|---|
| Data movement | `COPY`, `LOAD`, `STORE` |
| Arithmetic (sign-agnostic) | `ADD`, `SUB`, `NEG`, `MUL` |
| Arithmetic (sign-dependent) | `SDIV`, `UDIV`, `SMOD`, `UMOD` |
| Bitwise | `AND`, `OR`, `XOR`, `NOT`, `SHL`, `SHR`, `SAR` |
| Width conversion | `ZEXT`, `SEXT`, `TRUNC` |
| Comparison (always 1-bit result) | `EQ`, `NEQ`, `ULT`/`ULE`/`UGT`/`UGE`, `SLT`/`SLE`/`SGT`/`SGE` |
| Control flow | `JMP`, `CJMP`, `CALL`, `RET` |
| Symbolic | `UNDEF` — an unresolvable input (e.g. a register-offset addressing mode dragon-tales doesn't model yet) |

`CJMP` is worth calling out explicitly since operand order matters:
`srcs[0]` is the 1-bit condition, `srcs[1]` is the **taken** address,
`srcs[2]` is the **not-taken** address.

### Blocks

```cpp
const ignil::Block* ib = graph.getIGNILBlock(startAddress);
```

One `ignil::Block` per `BasicBlock` — same start address, same key you'd
pass to `graph.get_block()`. Iterate it directly (`for (const auto& op : *ib)`)
or grab `ops()`.

## Getting IGNIL out of a `Graph`

IGNIL is populated **in the same call** as the CFG/function analysis from
chapter 4 — there's no separate "now lift to IGNIL" step. The `Graph`-overload
`disassemble()` (C++) / `analyze()` (Python) does both at once:

{{< compare >}}
{{< pane lang="cpp" slot="first" >}}
dragon::Graph graph(dragon::Architecture::ARM64, config);
dis.disassemble(bytes, 0x1000, graph);   // CFG + functions + IGNIL, all at once

if (const dragon::ignil::Block* ib = graph.getIGNILBlock(0x1000)) {
    std::cout << dragon::ignil::toString(*ib);

    for (const dragon::ignil::Op& op : *ib) {
        std::cout << dragon::ignil::opcodeName(op.opcode) << "\n";
        if (op.dst)
            std::cout << "  dst: " << dragon::ignil::toString(*op.dst) << "\n";
        for (const auto& src : op.srcs)
            std::cout << "  src: " << dragon::ignil::toString(src) << "\n";
    }
}
{{< /pane >}}
{{< pane lang="python" slot="second" >}}
graph = disasm.analyze(raw, 0x1000)

ib = graph.get_ignil_block(0x1000)
print(ib.to_string())                 # multi-line text rendering, all ops

for addr, opcode_int, index in ib.ops():
    print(f"@0x{addr:x}  {dragon.IGNILOpcode.name(opcode_int)}")
{{< /pane >}}
{{< /compare >}}

`toString()`/`to_string()` is the quickest way to eyeball a block — it's
what the example programs use, and what's shown below.

## Register constants: `dragon::arm` / `dragon.arm`

Rather than hand-computing `Reg{offset, width}` for every register you want
to reference (e.g. when calling the backward slicer), both C++ and Python
expose named constants per architecture:

{{< compare >}}
{{< pane lang="cpp" slot="first" >}}
#include <dragon/lifters/ignil/arm/armIGNILRegs.hpp>
// dragon::arm::X0, dragon::arm::W0, dragon::arm::SP, dragon::arm::FP (alias for X29),
// dragon::arm::LR (alias for X30), dragon::arm::NF/ZF/CF/VF, dragon::arm::V0..V31, ...
{{< /pane >}}
{{< pane lang="python" slot="second" >}}
import dragon
dragon.arm.X0   # (0, 64, 'X0')
dragon.arm.W0   # (0, 32, 'W0')  — same offset as X0, 32-bit view
dragon.arm.FP   # (232, 64, 'FP') — alias for X29
dragon.arm.LR   # (240, 64, 'LR') — alias for X30
{{< /pane >}}
{{< /compare >}}

The equivalent for x86/x86-64 is `dragon::x86` / `dragon.x86` (`RAX`, `EAX`,
..., `CF`/`ZF`/`SF`/`OF`/... for EFLAGS bits) —
`include/dragon/lifters/ignil/x86/x86IGNILRegs.hpp`.

## Walking the running example

Same ARM64 `foo(x)` graph from chapters 3-4, now dumping its four IGNIL
blocks:

```python
for addr in graph.block_addresses():
    ib = graph.get_ignil_block(addr)
    print(ib.to_string())
```

Actual output:

```text
IGNILBlock @ 0x1000
  t0:i64 = ADD(SP:i64, 0xfffffffffffffff0:i64)  ; @0x1000
  STORE(t0:i64, FP:i64)  ; @0x1000
  t1:i64 = ADD(t0:i64, 0x8:i64)  ; @0x1000
  STORE(t1:i64, LR:i64)  ; @0x1000
  SP:i64 = COPY(t0:i64)  ; @0x1000
  t2:i64 = ADD(SP:i64, 0x0:i64)  ; @0x1004
  FP:i64 = COPY(t2:i64)  ; @0x1004
  t3:i32 = SUB(W0:i32, 0x0:i32)  ; @0x1008
  t4:i1 = SLT(t3:i32, 0x0:i32)  ; @0x1008
  NF:i8 = COPY(t4:i1)  ; @0x1008
  t5:i1 = EQ(t3:i32, 0x0:i32)  ; @0x1008
  ZF:i8 = COPY(t5:i1)  ; @0x1008
  t6:i1 = UGE(W0:i32, 0x0:i32)  ; @0x1008
  CF:i8 = COPY(t6:i1)  ; @0x1008
  t7:i1 = SLT(W0:i32, 0x0:i32)  ; @0x1008
  t8:i1 = SLT(0x0:i32, 0x0:i32)  ; @0x1008
  t9:i1 = SLT(t3:i32, 0x0:i32)  ; @0x1008
  t10:i1 = NEQ(t7:i1, t8:i1)  ; @0x1008
  t11:i1 = NEQ(t9:i1, t7:i1)  ; @0x1008
  t12:i1 = AND(t10:i1, t11:i1)  ; @0x1008
  VF:i8 = COPY(t12:i1)  ; @0x1008
  t13:i8 = COPY(ZF:i8)  ; @0x100c
  t14:i1 = NEQ(t13:i8, 0x0:i8)  ; @0x100c
  t15:i8 = COPY(NF:i8)  ; @0x100c
  t16:i8 = COPY(VF:i8)  ; @0x100c
  t17:i1 = NEQ(t15:i8, t16:i8)  ; @0x100c
  t18:i1 = OR(t14:i1, t17:i1)  ; @0x100c
  CJMP(t18:i1, 0x1018:i64, 0x1010:i64)  ; @0x100c

IGNILBlock @ 0x1010
  W0:i32 = COPY(0x1:i32)  ; @0x1010
  JMP(0x101c:i64)  ; @0x1014

IGNILBlock @ 0x1018
  W0:i32 = COPY(0xffffffff:i32)  ; @0x1018
  JMP(0x101c:i64)  ; @0x1018

IGNILBlock @ 0x101c
  t0:i64 = COPY(SP:i64)  ; @0x101c
  t1:i64 = ADD(SP:i64, 0x10:i64)  ; @0x101c
  t2:i64 = LOAD(t0:i64)  ; @0x101c
  FP:i64 = COPY(t2:i64)  ; @0x101c
  t3:i64 = ADD(t0:i64, 0x8:i64)  ; @0x101c
  t4:i64 = LOAD(t3:i64)  ; @0x101c
  LR:i64 = COPY(t4:i64)  ; @0x101c
  SP:i64 = COPY(t1:i64)  ; @0x101c
  RET()  ; @0x1020
```

A few things worth pointing out:

- **`stp x29, x30, [sp, #-16]!`** (block `0x1000`, first 5 ops) becomes
  explicit pointer arithmetic and two `STORE`s — IGNIL has no "store pair"
  primitive, so the lifter decomposes it into the address computation
  (`t0 = SP - 16`) and two individual stores at `t0` and `t0 + 8`.
- **`cmp w0, #0`** (block `0x1000`, `t3` through the `VF:i8 = COPY(...)` line)
  expands into computing all four AArch64 condition flags (`NF`/`ZF`/`CF`/`VF`)
  from the same subtraction — this is the "compute everything up front"
  strategy IGNIL uses so that whichever condition code a later branch
  needs (`b.le`, `b.ne`, ...) is already available as a flag register.
- **`b.le else_branch`** becomes the `OR` of a ZF check and an NF≠VF check
  (`t14 OR t17`) feeding a `CJMP` — that's the actual boolean definition of
  the ARM `LE` condition (`Z==1 OR N!=V`), not a special-cased opcode.
- **Blocks `0x1010` and `0x1018` both end in an explicit `JMP(0x101c)`**
  even though neither corresponds to a real ARM64 branch instruction —
  `0x1010`'s `b end_branch` does produce a real `JMP`, but `0x1018` falls
  through to `0x101c` with no branch instruction at all in the source. The
  lifter still materializes a `JMP` for it. This isn't incidental: a block
  with no terminator `Op` at all is invalid input to chapter 6's LLVM
  lifter (an LLVM basic block *must* end in a terminator), so `liftBlock()`
  explicitly synthesizes the fall-through edge from the block's known CFG
  successor whenever the source didn't already end in a branch.
- **`ldp x29, x30, [sp], #16`** (block `0x101c`) is the mirror of the
  `stp` above — two `LOAD`s reconstructing `FP`/`LR`, then `SP` advances.

## Scope

IGNIL lifting is implemented for **x86 (32/64) and ARM64** — see
`lib/disassemblers/x86/X86IGNILLifter.cpp` and
`lib/disassemblers/arm/armIGNILLifter.cpp`. ARM32 and RISC-V do not have a
lifter yet (RISC-V is decode-only end to end; ARM32 has full disassembly/
analysis but no IGNIL lifter). Known gaps even within x86/ARM64 — register-
offset addressing modes, some literal-pool forms, `ROR` shifts — lower to
an explicit `UNDEF` rather than silently producing a wrong value; check for
`UNDEF` in a block's ops if a slice or downstream analysis is coming back
empty.

Chapter 6 picks IGNIL up exactly where this chapter leaves it: `LLVMLifter`
consumes a `Function` and its blocks' `ignil::Block`s and produces real,
optimizable LLVM IR.
