---
title: "Getting Started"
weight: 1
summary: "Building dragon-tales and running your first snippet"
---

## Requirements

- LLVM 21 installed on the system (headers + libraries — `find_package(LLVM REQUIRED CONFIG)` needs `LLVM_DIR` to resolve to it)
- CMake 3.20+
- A C++20 compiler
- [Z3](https://github.com/Z3Prover/z3) — required by default (see build options below); needed for symbolic/SMT-based indirect-jump resolution
- Python 3 with `cffi` — only if you want to use the Python API

## Building

```sh
mkdir build && cd build
cmake ..
cmake --build .
```

This produces:

- `build/lib/libdragon.*` — the C++ core
- `build/c_shim/libdragon_c.so` — the C shim, used by both C and Python
- `build/bin/` — compiled examples (see [`examples/`](https://github.com/Fare9/dragon-tales/tree/main/examples))
- `build/tests` — the test binary

Confirm everything built correctly:

```sh
cd build
ctest --output-on-failure
```

> **Python note:** `python/dragon.py` locates the shim at a hardcoded path,
> `build/c_shim/libdragon_c.so`, relative to the repo root. If you use a
> differently-named build directory (`cmake-build-debug`, `out`, ...), the
> Python API won't find the library — either build into a directory named
> `build/`, or symlink/copy the `.so` into place.

## Build options

Two `cmake` flags control what gets built, both `ON` by default:

| Option | Default | Effect |
|---|---|---|
| `DRAGON_USE_Z3` | `ON` | Links Z3 for SMT-based indirect-jump/path discovery (`BackwardSlicer`'s Z3-backed solving). Requires Z3 to be installed (`find_package(Z3 REQUIRED)` — on Debian/Ubuntu, the system `apt` package works via LLVM's `FindZ3` module). Pass `OFF` if you don't have Z3 available and don't need symbolic solving. |
| `DRAGON_BUILD_TESTS` | `ON` | Builds the Catch2 test suite (`build/tests`) and registers it with `ctest`. Pass `OFF` for a leaner build if you only want the libraries/examples. |

```sh
# Example: skip Z3 and tests for a minimal build
cmake .. -DDRAGON_USE_Z3=OFF -DDRAGON_BUILD_TESTS=OFF
cmake --build .
```

## Your first snippet

A minimal sanity check that the toolchain and library are wired up
correctly: assemble two x86-64 instructions, then disassemble them back.

{{< compare >}}
{{< pane lang="cpp" slot="first" >}}
#include <dragon/assembler/Assembler.hpp>
#include <dragon/disassembler/Disassembler.hpp>
#include <iostream>

int main() {
    dragon::Configuration config;  // INTEL syntax, generic CPU, by default

    dragon::Assembler asm_(dragon::Architecture::X86_64, config);
    auto bytes = asm_.assemble("nop\nret\n");

    dragon::Disassembler dis(dragon::Architecture::X86_64, config);
    for (const auto& insn : dis.disassemble(bytes, /*baseAddress=*/0x1000))
        std::cout << std::hex << insn.address() << "  " << insn.disassembly() << "\n";
    // 1000  nop
    // 1001  ret
}
{{< /pane >}}
{{< pane lang="python" slot="second" >}}
import dragon

config = dragon.Configuration(syntax=dragon.Syntax.INTEL)

asm = dragon.Assembler(dragon.Architecture.X86_64, config)
raw = asm.assemble("nop\nret\n")

disasm = dragon.Disassembler(dragon.Architecture.X86_64, config)
graph = disasm.disassemble(raw, 0x1000)
for insn in graph.instructions():
    print(f"{insn.address:x}  {insn.mnemonic} {insn.operands}")
# 1000  nop
# 1001  ret
{{< /pane >}}
{{< /compare >}}

If this prints the two instructions back, you're set up correctly. The next
two chapters look at `Assembler` and `Disassembler` in more depth before
chapter 4 introduces `Graph`, the structure both snippets above are quietly
already using under the hood.
