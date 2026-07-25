---
title: "The Manual"
---

A hands-on walkthrough of dragon-tales, from raw bytes to optimized LLVM IR.
Unlike the API references (`cpp_api.md`, `c_api.md`, `python_api.md` in the
repository), which are organized by class and function, this manual is
organized by *task*: each chapter builds on the previous one, using one
running example — a small ARM64/x86-64 function — all the way through the
pipeline.

Every code snippet in this manual is runnable as-is; most are lightly
trimmed versions of the example programs under `examples/` in the repository.

## Which API layer?

Examples are shown in **C++** and **Python** side by side, with a slider,
wherever the two diverge meaningfully. The C shim (`c_shim/dragon_c.h`) is the
same shape as the Python API — it's what the Python bindings wrap — see
`docs/c_api.md` in the repository if you're integrating from C directly.
