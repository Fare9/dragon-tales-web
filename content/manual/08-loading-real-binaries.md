---
title: "Loading Real Binaries"
weight: 8
summary: "From an ELF or PE file on disk straight to a populated Graph — no objdump"
---

Every byte stream so far came from one of two places: dragon-tales' own
`Assembler`, or a `.text` section a reader extracted by hand. That hand
extraction — `objdump` to look, `objcopy` to carve out the raw section — is
what [chapter 9](../09-a-real-world-example/) walks through, and it's worth
understanding once. But real analysis starts from a *file*: an ELF or a PE,
with a header, a section table, a symbol table, and an entry point. The
**loader** reads that container directly and hands you back something the rest
of the pipeline already understands.

The parse is delegated to LLVM's own `llvm::object` library — already a
dependency of `libdragon`, so nothing new is pulled in — and everything LLVM
returns is copied out into plain owned structures. A `LoadedImage` carries no
LLVM types on its surface, which is exactly what lets the C shim and the
Python API wrap it without exposing an LLVM header.

## The example binary

The running example here is a real, protected Windows executable:
`serial_check.protected.exe`, the VMProtect-protected target from the
companion VMProtect analysis that this library is developed alongside. It's a
good stress case precisely because it is *not* a clean compiler output — a
protector has rewritten its section layout, which is the first thing a loader
lets you see.

A dependency-free PE parser was written by hand for that analysis
(`pe_report.py`: ~180 lines of `struct.unpack` walking the MZ/PE headers, the
section table, and the import directory). The loader does the same job as a
built-in — and across ELF and PE, 32- and 64-bit, from one API.

## Loading an image

{{< compare >}}
{{< pane lang="cpp" slot="first" >}}
#include <dragon/loader/Loader.hpp>

std::string error;
auto image = dragon::loader::LoadedImage::loadFile(
    "serial_check.protected.exe", &error);
if (!image) {
    std::cerr << "load failed: " << error << "\n";
    return 1;
}
// loadBytes(std::vector<std::uint8_t>) loads from an in-memory blob instead.
{{< /pane >}}
{{< pane lang="python" slot="second" >}}
import dragon

# Raises ValueError (with the reason) on any failure.
img = dragon.LoadedImage.load_file("serial_check.protected.exe")
# dragon.LoadedImage.load_bytes(data) loads from a bytes object instead.
{{< /pane >}}
{{< /compare >}}

Loading succeeds or it doesn't: a missing file, an unreadable one, something
that isn't an object file, or a truncated one all fail — C++ returns
`std::nullopt` (with a one-line reason in `error`), Python raises `ValueError`.

## Image-level facts

The header tells you what you're looking at before a single instruction is
decoded — and notably, the **architecture comes from the file**, so you never
name it by hand the way every earlier chapter did:

```python
print(img.format == dragon.Format.PE)                     # True
print(img.architecture == dragon.Architecture.X86_64)     # True
print(img.is_64bit)                                       # True
print(hex(img.image_base))                                # 0x140000000
print(hex(img.entry))                                     # 0x1401c73ae
```

`entry` is the absolute virtual address of the entry point (image base already
applied), or `None`/`std::nullopt` for a format that has none — a relocatable
object (`.o`/`.obj`), or a DLL/`.so` with no entry. For a relocatable object,
also check `hasVirtualLayout()` (C++): its sections sit at address 0 rather
than at real virtual addresses.

## Sections

`sections()` returns every section placed at its virtual address, with
permissions and the file-provided bytes:

```python
for s in img.sections():
    print(s)
```

```text
<Section '.text'  @0x140001000 size=0x82fdb  r-x>
<Section '.rdata' @0x140084000 size=0x16d8e  r-->
<Section '.data'  @0x14009b000 size=0x30e1   rw->
...
<Section './A('   @0x1400a9000 size=0x1067fc r-x>   # junk-named, executable
<Section '.\UY'   @0x1401b0000 size=0x640    rw->
<Section '.Cot'   @0x1401b1000 size=0x3fba4  r-x>   # entry 0x1401c73ae lives here
<Section '.reloc' @0x1401f1000 size=0xa80    r-->
```

That listing *is* the protection, in plain sight. A normal MSVC binary has
`.text`, `.rdata`, `.data`, `.pdata`, `.reloc`; this one has three extra
executable/writable sections with garbage names (`./A(`, `.\UY`, `.Cot` —
names that contain non-printable bytes, which is itself a tell), and the entry
point at `0x1401c73ae` doesn't land in `.text` at all — it lands in `.Cot`,
the VM. `sectionContaining(addr)` (C++) answers that "which section holds the
entry?" question directly; the handful of lines above are what the hand-rolled
`pe_report.py` heuristics flagged, now read straight off the parsed image.

A `Section` whose mapped size is non-zero but whose `bytes` are empty is a
BSS-style section (`.bss`, PE uninitialised data). `readVirtual(addr, size)`
(Python `read_virtual`) reads across whatever section covers an address and
zero-fills any BSS tail, matching what the OS loader would map — or returns
`None`/`std::nullopt` if the range isn't mapped.

## Symbols, imports and exports

```python
syms   = img.symbols()                                   # everything
imports = [s for s in syms if s.imported]                # undefined externals
exports = [s for s in syms if s.exported]                # defined globals
```

C++ exposes the filtered views as methods — `imports()`, `exports()`,
`definedSymbols()` — plus `functionAt(addr)`, the function-typed symbol
defined exactly at an address, which is what seeds and *names* recovered
functions. An `imported` symbol is one the image expects the loader to supply
(a DLL/libc import); its `address` isn't meaningful. This PE imports from a
single DLL — `KERNEL32.dll` — which is itself unusual for a program this size
and another consequence of the protector rewriting the import table.

## Straight to a Graph

The payoff: one call disassembles every executable section, each at its own
virtual address so cross-section calls and jumps resolve, into a `Graph` built
for the architecture the image declares. The entry point and every
function-typed symbol are registered as function starts.

{{< compare >}}
{{< pane lang="cpp" slot="first" >}}
#include <dragon/loader/ImageDisassembler.hpp>

dragon::Configuration config;                    // defaults are fine
dragon::Graph graph = dragon::loader::disassembleImage(*image, config);
// graph now holds blocks/functions/IGNIL for every executable section,
// exactly like the graphs of chapters 4-7 — feed it straight to LLVMLifter.
{{< /pane >}}
{{< pane lang="python" slot="second" >}}
graph = img.disassemble()                        # optional config= argument
# Same Graph the earlier chapters built by hand — block_addresses(),
# get_function(addr), get_ignil_block(addr), LLVMLifter all apply unchanged.
{{< /pane >}}
{{< /compare >}}

From here the binary is just another `Graph`: everything in chapters 4
through 7 — blocks, functions, IGNIL, the LLVM lifter — applies without
change. For a protected target like this one, that `Graph` is the *starting*
point for the real work (locating the VM entry, classifying handlers,
devirtualizing), which is the subject of the companion VMProtect write-up, not
of this manual. For an ordinary ELF/PE it's the whole game: load, disassemble,
analyze.

## Recovering function signatures

Once a function is in the `Graph`, one more analysis takes it from "a blob of
lifted code" toward "something with a prototype": **argument recovery**. It's
the forward counterpart to the backward slicer — the slicer asks what one
value depends on; this asks what a whole function *consumes and produces*.

The core is an ordinary live-variable analysis over the function's IGNIL CFG:
a register read along some path from the entry before it is written is
*live-in* — the function expects the caller to have set it. Intersect the
live-in set with the target's calling convention (which registers carry the
first N integer arguments) and you have the argument list; the convention's
return register, if the body ever writes it, is the return value.

> **C++ only, for now.** `dragon::analysis::recoverSignature` and its helpers
> live in `<dragon/analysis/ArgumentRecovery.hpp>` and are not yet exposed
> through the C shim or the Python API — unlike the loader above, which is in
> both.

```cpp
#include <dragon/analysis/ArgumentRecovery.hpp>
#include <dragon/disassembler/Function.hpp>

// A tiny x86-64 function: mov eax, edi ; add eax, esi ; ret
//   (reads EDI and ESI, returns through EAX)
dragon::Function fn(&graph, 0x1000);

auto sig = dragon::analysis::recoverSignature(fn, graph,
                                              dragon::Architecture::X86_64);

std::cout << dragon::analysis::toString(sig, 0x1000) << "\n";
// i32 sub_1000(i32 RDI, i32 RSI)
```

`liveInRegisters(fn, graph)` exposes the raw live-in set if you want it
(RSP/RBP/flags appear there too and are filtered out of the signature). The
widths are read off the IGNIL — a function that only ever touches `EDI`
reports an `i32` argument, not `i64`.

What it recovers is the common integer/pointer ABI shape, deliberately not
every corner of it. The documented limits:

- **Integer class only** — floating-point/vector (XMM/SIMD) arguments,
  register-passed structs, and stack-passed arguments beyond the register
  count are not recovered.
- **Register-offset granularity** — a read of `EDI` counts as a use of the
  `RDI` slot; sub-register width is consulted only to size the result.
- **Arguments are the contiguous convention prefix** up to the highest live-in
  argument register, matching how compilers actually allocate them.
- **Two conventions modelled** — x86-64 System V and AArch64 AAPCS64.

## Where to go from here

The loader closes the gap between "a file on disk" and the `Graph` the rest of
the manual operates on. [Chapter 9](../09-a-real-world-example/) runs a real
compiled function through the whole pipeline (and shows where the current
lifter's edges are); [chapter 10](../10-symbolic-execution/) then asks the
code questions static reading can't answer.
