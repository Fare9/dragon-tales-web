---
title: "Assembling Your Code"
weight: 2
summary: "Turning assembly text into raw machine bytes"
---

`Assembler` turns architecture-specific assembly text into raw machine code
bytes. It's the mirror image of `Disassembler` (next chapter) and is useful
any time you want to generate test input without hand-encoding bytes, patch
shellcode, or build fixtures for the later chapters of this manual — every
byte sequence used from here on was itself produced by `Assembler`.

It wraps LLVM's own assembler (`MC`) for the target, so anything LLVM's
`llvm-mc` can assemble for a given triple, `Assembler` can too — including
labels, local jumps, and directives.

## The `Assembler` class

- One `Assembler` instance can call `assemble()` as many times as you like — it's stateless per call.
- `isValid()` is `false` only for `Architecture::Unknown` or if LLVM's target init failed; all six architectures in the `Architecture` enum are otherwise valid.

> **Error handling differs by layer.** The C++ `assemble()` returns an
> **empty vector** on failure (bad syntax, unsupported instruction for the
> configured CPU, ...) — check `bytes.empty()`, nothing is thrown. The
> Python wrapper instead **raises `RuntimeError`** on failure — same
> underlying C shim call (`dragon_asm_assemble`), different failure
> convention per language idiom.

{{< compare >}}
{{< pane lang="cpp" slot="first" >}}
dragon::Configuration config;                 // INTEL syntax, generic CPU, by default
dragon::Assembler asm_(dragon::Architecture::X86_64, config);

if (!asm_.isValid()) { /* unsupported architecture / LLVM init failure */ }

std::vector<std::uint8_t> bytes = asm_.assemble("nop\nret\n");
{{< /pane >}}
{{< pane lang="python" slot="second" >}}
import dragon

config = dragon.Configuration(syntax=dragon.Syntax.INTEL)
asm = dragon.Assembler(dragon.Architecture.X86_64, config)

try:
    raw = asm.assemble("nop\nret\n")
except RuntimeError:
    ...  # assembly failed
{{< /pane >}}
{{< /compare >}}

## x86-64

```cpp
dragon::Configuration config;
dragon::Assembler asm_(dragon::Architecture::X86_64, config);

auto bytes = asm_.assemble("nop\nret\n");
// bytes == { 0x90, 0xC3 }
```

**AT&T syntax** — set `config.syntax` before constructing the assembler.
Instructions with no operands encode identically either way (`nop`/`ret`);
the difference matters once operands are involved (`retq`, `%`-prefixed
registers, source/dest order):

```cpp
dragon::Configuration att;
att.syntax = dragon::Syntax::ATT;

dragon::Assembler attAsm(dragon::Architecture::X86_64, att);
auto bytes = attAsm.assemble("retq\n");
```

**Labels and local jumps** work exactly as in a normal `.s` file — the
assembler resolves them at assemble time:

```cpp
dragon::Assembler asm_(dragon::Architecture::X86_64, config);
auto bytes = asm_.assemble(R"(
    xor eax, eax
    test edi, edi
    je  skip
    mov eax, 1
skip:
    ret
)");
```

**CPU targeting** works the same way as ARM below — `cpu`/`features` select
which instruction extensions are available:

```cpp
dragon::Configuration config;
config.cpu = "skylake-avx512";     // enables AVX-512
// or, equivalently for a specific extension:
config.features = "+avx2,+bmi2";
```

## x86-32

Identical API — only `Architecture::X86_32` changes. Instruction encodings
differ (no REX prefixes, 32-bit-width defaults):

```cpp
dragon::Configuration config;
dragon::Assembler asm_(dragon::Architecture::X86_32, config);

auto nopBytes = asm_.assemble("nop");   // { 0x90 } — same 1-byte encoding as x86-64
auto retBytes = asm_.assemble("ret");   // { 0xC3 } — same 1-byte encoding as x86-64
```

`nop` and `ret` happen to encode identically to their x86-64 counterparts
here; that stops being true the moment operands or wider registers show up
(`eax`-only addressing, no `rax`/`r8`-`r15`, no REX-prefixed forms).

## ARM32

Same API, `Architecture::ARM32`. The critical thing to understand about ARM32
is that **`cpu`/`features` gate which instructions exist at all**, not just
which ones get optimized for — the generic baseline targets ARMv4 and does
*not* include `HasV4TOps`, so even `bx lr` fails to assemble against the
default configuration:

```cpp
dragon::Configuration config;                 // generic baseline: plain ARMv4
dragon::Assembler asm_(dragon::Architecture::ARM32, config);
asm_.assemble("bx lr");                       // fails — empty vector: no BX before ARMv4T
```

Pick a `cpu` (a specific core) or set `features` directly (individual ISA
extensions) to unlock what you need. Real LLVM 21 core names for ARM32,
grouped by architecture revision:

| Architecture revision | Example `cpu` values | Adds over the previous revision |
|---|---|---|
| ARMv4T | `arm7tdmi`, `arm9tdmi` | Thumb instruction set, `BX`/`BLX` |
| ARMv5TE | `arm926ej-s`, `arm10e` | DSP extensions, `BLX` immediate, saturating arithmetic |
| ARMv6 | `arm1136j-s`, `arm1176jzf-s` | SIMD instructions, unaligned memory access, `MOVW`/`MOVT` |
| ARMv7-A | `cortex-a8`, `cortex-a9`, `cortex-a15` | Thumb-2, NEON (with `+neon`), VFPv3 |
| ARMv7-M | `cortex-m3`, `cortex-m4` | Microcontroller profile — Thumb-only, no ARM (A32) encoding, no NEON |
| ARMv8-A (32-bit mode) | `cortex-a32`, `cortex-a35` | AArch32 execution state of an ARMv8-A core |

Individual feature flags, if you'd rather not commit to a specific core:

| `features` string | Effect |
|---|---|
| `"+v4t"` | Adds `BX`/`BLX` (ARMv4T) without picking a specific core |
| `"+v6"` | ARMv6 baseline (SIMD, unaligned access) |
| `"+v7,+thumb2"` | ARMv7 with Thumb-2 |
| `"+v7,+neon"` | ARMv7-A with NEON SIMD |
| `"+vfp3"` | VFPv3 floating point, without committing to NEON |

```cpp
// Same effect, two ways of expressing "give me BX":
dragon::Configuration byCpu;
byCpu.cpu = "arm926ej-s";        // ARMv5TEJ

dragon::Configuration byFeature;
byFeature.features = "+v4t";

// A Thumb-2 + NEON target:
dragon::Configuration thumb2Neon;
thumb2Neon.cpu = "cortex-a8";
```

## ARM64 (AArch64)

Same API, `Architecture::ARM64`. Unlike ARM32, the **generic AArch64
baseline is already a complete ARMv8-A core** — no `cpu`/`features` needed
for ordinary code. It's also a fixed-width instruction set: every
instruction assembles to exactly 4 bytes, regardless of mnemonic:

```cpp
dragon::Configuration config;                 // generic is fine for ARM64
dragon::Assembler asm_(dragon::Architecture::ARM64, config);

auto nopBytes = asm_.assemble("nop");         // 4 bytes
auto retBytes = asm_.assemble("ret");         // 4 bytes
auto bytes    = asm_.assemble("nop\nret\n");  // 8 bytes total
```

`cpu`/`features` become relevant once you need a specific extension or want
to model a specific chip. Real LLVM 21 core names, by category:

| Category | Example `cpu` values | Notes |
|---|---|---|
| Early ARMv8.0-A | `cortex-a53`, `cortex-a57` | The two most common baseline 64-bit cores (e.g. early Raspberry Pi 4/AWS Graviton-class) |
| ARMv8.2-A and later | `cortex-a55`, `cortex-a75`, `cortex-a76`, `cortex-a78` | Adds dot-product, fp16 by default depending on core |
| Apple silicon | `apple-a14` … `apple-a18`, `apple-m1` … `apple-m4` | Apple's AArch64 implementations |
| Server-class | `neoverse-n1`, `neoverse-v2`, `ampere1`, `thunderx2t99` | Datacenter cores; some enable SVE/SVE2 by default (e.g. `neoverse-v1`) |
| Vector-heavy | `a64fx` | Fujitsu's SVE-first design (512-bit SVE) |

Individual feature flags:

| `features` string | Effect |
|---|---|
| `"+sve"` | Scalable Vector Extension |
| `"+sve2"` | SVE2 (superset of SVE) |
| `"+crypto"` | AES/SHA cryptographic instructions |
| `"+dotprod"` | Dot-product instructions (common in ML-adjacent cores) |
| `"+lse"` | Armv8.1-A Large System Extension atomics |
| `"+bf16"` | BFloat16 extension |

```cpp
dragon::Configuration sve;
sve.features = "+sve";

dragon::Configuration appleM1;
appleM1.cpu = "apple-m1";
```

### The running example: an ARM64 branch

The rest of this manual follows one function through the whole pipeline —
disassembly, CFG/function recovery, IGNIL, and LLVM IR. It's a small ARM64
function equivalent to `int foo(int x) { return x > 0 ? 1 : -1; }`, with an
explicit stack frame, a comparison, and a conditional branch:

```python
import dragon

cfg = dragon.Configuration(syntax=dragon.Syntax.INTEL)
asm = dragon.Assembler(dragon.Architecture.ARM64, cfg)

asm_src = """
foo:
    stp x29, x30, [sp, #-16]!
    mov x29, sp
    cmp w0, #0
    b.le else_branch
    mov w0, #1
    b end_branch
else_branch:
    mov w0, #-1
end_branch:
    ldp x29, x30, [sp], #16
    ret
"""

raw = asm.assemble(asm_src)
print(raw.hex())
```

This matches [`example.py`](https://github.com/Fare9/dragon-tales/blob/main/example.py)
at the repo root. We'll disassemble these exact bytes in the next chapter,
then follow them through IGNIL and LLVM IR in chapters 5 and 6.

## RISC-V 32/64

Same API again, `Architecture::RISCV32` / `Architecture::RISCV64`. Assembly
works via LLVM's generic RISC-V target regardless of extensions enabled;
`cpu`/`features` gate which instructions are *available* to assemble, the
same way they do for x86/ARM:

```cpp
dragon::Configuration config;
config.features = "+m,+a,+c";   // multiply, atomics, compressed

dragon::Assembler asm_(dragon::Architecture::RISCV64, config);
auto bytes = asm_.assemble("addi a0, a0, 1\nret\n");
```

> **Scope note:** RISC-V assembly/disassembly is fully supported, but the
> IGNIL lifter and function/CFG analysis (chapters 4-6) are not yet
> implemented for RISC-V — see [IDEAS.md](https://github.com/Fare9/dragon-tales/blob/main/docs/manual/IDEAS.md).
> The examples in the rest of this manual use x86-64 and ARM64, the two
> architectures with full pipeline support today.
