---
title: "dragon-tales"
---

## What is dragon-tales?

dragon-tales is a binary analysis library for disassembling, assembling, and
analyzing machine code across multiple architectures. It's built on **LLVM 21**,
so decoding is as accurate as LLVM's own MC layer, and every architecture LLVM
knows about is a realistic target for dragon-tales to grow into.

Everything is object-based, top to bottom. A `Configuration` object — syntax,
disassembly strategy, target CPU, target features — is constructed once and
handed to a `Disassembler` or `Assembler`. There's no free-function API to
half-remember; the same shape shows up whether you're in C++, calling the
C shim directly, or using the Python bindings that wrap it.

## Three layers, one API shape

- **C++ core** (`include/dragon/`, `lib/`) — the real implementation:
  `Configuration`, `Disassembler`, `Assembler`, `Graph`, `BasicBlock`,
  `Function`, `Instruction`.
- **C shim** (`c_shim/dragon_c.h`) — an opaque-pointer C API wrapping the C++
  layer, for anything that needs a stable C ABI.
- **Python** (`python/dragon.py`) — `cffi` bindings over the C shim, so the
  Python API mirrors the C++ one almost 1:1.

## From bytes to IR

The pipeline goes further than "print the disassembly." Once instructions are
recovered, dragon-tales reconstructs basic blocks and functions into a control-flow
graph, lifts that graph into **IGNIL** — a small architecture-independent
intermediate language — and can move IGNIL into optimizable **LLVM IR** for
further analysis or transformation. A **backward slicer** walks IGNIL CFGs to
answer questions like "where did this flag actually come from?" without
crossing block joins.

## Where to go next

The [manual](manual/) walks through the whole pipeline hands-on, one running
example (a small ARM64/x86-64 function) all the way from raw bytes to LLVM IR.
For reference material organized by class and function instead, see
[`docs/cpp_api.md`](https://github.com/Fare9/dragon-tales/blob/main/docs/cpp_api.md),
[`docs/c_api.md`](https://github.com/Fare9/dragon-tales/blob/main/docs/c_api.md), and
[`docs/python_api.md`](https://github.com/Fare9/dragon-tales/blob/main/docs/python_api.md)
in the repository.
