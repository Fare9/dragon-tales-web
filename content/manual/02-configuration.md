---
title: "Configuration"
weight: 2
summary: "The one value object every Assembler, Disassembler and loader takes"
---

Every entry point in the previous chapter's snippet took a `Configuration`
as its second argument, and every chapter after this one does too — the
`Assembler`, the `Disassembler`, and the loader of [chapter 8](../08-loading-real-binaries/)
all share it. It's a small, copyable value object: construct one, set the
fields you care about, and hand it in. **Leaving it at its defaults is always
safe** — INTEL syntax, linear-sweep disassembly, and the most conservative
("generic") CPU baseline for the target architecture.

This chapter is the one place the whole object is documented end to end; the
later chapters reach for individual fields (`syntax` in [chapter 3](../03-assembling-your-code/),
`disassemblyStrategy` in [chapter 4](../04-disassembling-your-first-binary/),
`cpu`/`features` throughout) as they need them.

## The fields

| Field | Type | Default | What it controls |
|---|---|---|---|
| `syntax` | `Syntax` | `INTEL` | Assembly syntax for both input (assembler) and printed output (disassembler): `INTEL` or `ATT`. |
| `disassemblyStrategy` | `DisassemblyStrategy` | `LINEAR_SWEEP` | How the disassembler walks bytes: `LINEAR_SWEEP` (front to back) or `RECURSIVE_TRAVERSAL` (follow control flow). Ignored by the assembler. |
| `cpu` | `std::string` | `""` | LLVM CPU name forwarded to `MCSubtargetInfo`. Empty selects LLVM's generic baseline for the triple, which may omit optional ISA extensions. |
| `features` | `std::string` | `""` | Comma-separated LLVM feature flags, each prefixed `+` (enable) or `-` (disable). Combined with whatever `cpu` already implies. |
| `logging` | `bool` | `false` | When `true`, the library writes diagnostic messages to `stderr`. Off by default so a library user isn't surprised by output. |
| `useZ3ForPathDiscovery` | `bool` | `false` | **C++ only, Z3 builds only.** When `true`, the disassembler calls Z3 to enumerate indirect-jump targets the backward slicer can't fold to a constant. See [chapter 10](../10-symbolic-execution/). |

The last field only exists when the library is built with Z3
(`-DDRAGON_USE_Z3=ON`, the default — see [chapter 1](../01-getting-started/));
the struct member is compiled out entirely otherwise, and it is not exposed
by the C shim or the Python API.

## Constructing one

{{< compare >}}
{{< pane lang="cpp" slot="first" >}}
#include <dragon/Configuration.hpp>

// Defaults: INTEL syntax, LINEAR_SWEEP, generic CPU, no logging.
dragon::Configuration config;

// Or set fields directly — it's a plain struct.
config.syntax = dragon::Syntax::ATT;
config.disassemblyStrategy = dragon::DisassemblyStrategy::RECURSIVE_TRAVERSAL;
config.cpu = "skylake";
config.features = "+avx2";
config.logging = true;
{{< /pane >}}
{{< pane lang="python" slot="second" >}}
import dragon

# Defaults: INTEL syntax, LINEAR_SWEEP, generic CPU, no logging.
config = dragon.Configuration()

# Keyword arguments at construction, or assign to the properties after.
config = dragon.Configuration(
    syntax=dragon.Syntax.ATT,
    strategy=dragon.Strategy.RECURSIVE_TRAVERSAL,
    cpu="skylake",
    features="+avx2",
    logging=True,
)
config.cpu = "znver3"   # cpu / features / logging are settable properties
{{< /pane >}}
{{< /compare >}}

> **One naming difference between the two APIs.** The C++ struct field is
> `disassemblyStrategy` and its enum is `dragon::DisassemblyStrategy`; the
> Python constructor argument is `strategy` and its enum is `dragon.Strategy`.
> The values (`LINEAR_SWEEP`, `RECURSIVE_TRAVERSAL`) match. Syntax is
> `dragon::Syntax` / `dragon.Syntax` in both, with `INTEL` and `ATT`.

## Syntax

`INTEL` is the default and the one most reverse-engineering tooling uses
(`mov eax, 1`); `ATT` is GAS/GNU style (`movl $1, %eax`). It controls how the
assembler *reads* your input and how the disassembler *prints* its output —
the raw bytes in between are identical either way. [Chapter 3](../03-assembling-your-code/)
shows the same two instructions assembled under each syntax.

## Disassembly strategy

`LINEAR_SWEEP` decodes straight through the byte range from first to last;
`RECURSIVE_TRAVERSAL` starts at known entry points and follows branches.
Which one recovers the intended instruction stream — and why the choice
matters for real, interleaved code and data — is the subject of
[chapter 4](../04-disassembling-your-first-binary/). The assembler ignores
this field.

## `cpu` and `features`

These are passed straight through to LLVM's subtarget machinery, so the
accepted values are exactly LLVM's: a `cpu` names a micro-architecture
(`cortex-a8`, `arm926ej-s`, `skylake`, `sifive-u74`), and `features` is a
comma-separated list of fine-grained flags combined with what the CPU already
implies:

| Example `features` | Meaning |
|---|---|
| `+v4t` | enable ARMv4T on ARM32 (adds the `bx` instruction) |
| `+v7,+neon` | ARMv7 with NEON |
| `+avx2` | enable AVX2 on x86 |
| `+m,+a,+c` | RISC-V multiply, atomics, compressed |

They gate which instructions can be *assembled* and *decoded*: a disassembler
left at the generic ARM32 baseline won't decode `bx`, for instance. Because
they're the knob you reach for most when a real target isn't plain-baseline,
every architecture section of [chapter 3](../03-assembling-your-code/) works
through concrete `cpu`/`features` combinations.

## Logging and Z3

`logging` is a simple on/off for diagnostic output to `stderr`; keep it off in
library code and flip it on while debugging a decode that comes back empty or
short.

`useZ3ForPathDiscovery` only does something in a Z3-enabled build, and only
helps when the disassembler hits an indirect jump (a `jmp rax`, a jump table)
whose target the backward slicer can't pin to a single constant on its own.
Turning it on lets the disassembler ask the solver to enumerate the reachable
targets so those edges make it into the CFG. It's off by default because it
costs solver time on every unresolved indirect branch; [chapter 10](../10-symbolic-execution/)
covers the symbolic machinery behind it, including resolving a computed jump
end to end.

With the configuration understood, the next two chapters put it to work: the
assembler in chapter 3, the disassembler in chapter 4.
