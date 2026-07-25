---
title: "Disassembling Your First Binary"
weight: 3
summary: "Turning bytes back into instructions"
---

`Disassembler` turns raw bytes back into structured `Instruction` objects.
It's the mirror image of `Assembler` from the last chapter, and — unlike
the assembler — it comes in **two distinct modes**: a flat, structure-free
listing, and a fully analyzed `Graph` with basic blocks and functions
recovered. Picking the right one matters, so this chapter spends some time
on the difference before moving to the `Instruction` API itself.

## The `Disassembler` class

```cpp
#include <dragon/disassembler/Disassembler.hpp>

dragon::Configuration config;   // INTEL syntax, LINEAR_SWEEP, generic CPU, by default
dragon::Disassembler dis(dragon::Architecture::X86_64, config);

if (!dis.isValid()) { /* unsupported architecture / LLVM init failure */ }
```

Same construction pattern as `Assembler`: pass an `Architecture` and a
`Configuration`, check `isValid()`. The `cpu`/`features` fields from
chapter 2 apply here identically — a disassembler configured for the
generic ARM32 baseline won't decode `bx`, the exact same restriction that
applied to assembling it.

## Mode 1 — flat listing (no structure)

`disassemble(bytes, baseAddress)` decodes every instruction it can find and
returns a plain `std::vector<Instruction>` in address order. It does **not**
detect basic blocks or functions — every `Instruction`'s structural flags
(`isBlockStart()`, `isFunctionStart()`, `isPrologue()`) are left at their
default `false`.

{{< compare >}}
{{< pane lang="cpp" slot="first" >}}
std::vector<uint8_t> bytes = { 0x90, 0xC3 };  // nop; ret

auto instrs = dis.disassemble(bytes, /*baseAddress=*/0x1000);
for (const auto& insn : instrs)
    std::cout << std::hex << insn.address() << "  " << insn.disassembly() << "\n";
// 1000  nop
// 1001  ret
{{< /pane >}}
{{< pane lang="python" slot="second" >}}
import dragon

config = dragon.Configuration(syntax=dragon.Syntax.INTEL)
disasm = dragon.Disassembler(dragon.Architecture.X86_64, config)

graph = disasm.disassemble(bytes([0x90, 0xC3]), 0x1000)
for insn in graph.instructions():
    print(f"{insn.address:x}  {insn.mnemonic} {insn.operands}")
{{< /pane >}}
{{< /compare >}}

> **Python detail:** `Disassembler.disassemble()` in Python/C still returns
> a `Graph` object (for a consistent interface with `analyze()`, below,
> and so `graph.instructions()`/`graph.get_instruction()` work) — but
> internally it's built by decoding the flat list and inserting each
> instruction with `addInstruction()`, exactly like the C++ flat path.
> **No block or function analysis runs.** `graph.block_addresses()` and
> `graph.function_addresses()` will be empty after a plain `disassemble()`
> call — you need `analyze()` (mode 2) for those.

Use this mode when you just want to decode a buffer and don't need CFG or
function recovery — e.g. printing a listing, or as input to a
pattern-matching / signature pass over `pattern()` and `chromosomeMask()`.

## Mode 2 — full analysis (`Graph` + CFG + functions)

The `Graph`-taking overload runs the architecture-specific analysis pass
(`X86Analysis`/`ARMAnalysis` internally) that discovers prologues, delineates
basic blocks at every branch target, and recovers function boundaries —
all in one call:

{{< compare >}}
{{< pane lang="cpp" slot="first" >}}
#include <dragon/disassembler/Graph.hpp>

dragon::Graph graph(dragon::Architecture::X86_64, config);
dis.disassemble(bytes, 0x1000, graph);   // note: void return, graph is populated in place

for (const auto& block : graph.blocks())
    std::cout << "block @ 0x" << std::hex << block.startAddress() << "\n";
for (const auto& fn : graph.functions())
    std::cout << "function @ 0x" << std::hex << fn.startAddress() << "\n";
{{< /pane >}}
{{< pane lang="python" slot="second" >}}
graph = disasm.analyze(bytes([...]), 0x1000)   # Python's name for the Graph-overload
print(graph.block_addresses())
print(graph.function_addresses())
{{< /pane >}}
{{< /compare >}}

Chapter 4 covers `BasicBlock` and `Function` in depth — this chapter only
establishes *which call gets you there*.

> **A pitfall worth naming explicitly:** it's tempting to build a `Graph`
> yourself by decoding a flat listing and inserting each instruction one at
> a time:
> ```cpp
> dragon::Graph graph(dragon::Architecture::X86_64, config);
> for (auto& insn : dis.disassemble(bytes, 0x1000))
>     graph.addInstruction(std::move(insn));
> ```
> This compiles, and `graph.get(address)` works — but **no block or
> function analysis has run**, so `graph.blocks()` and `graph.functions()`
> come back empty and any `BasicBlock`/`Function` view constructed against
> that address reports `isValid() == false`. This was verified directly:
> the manual insertion loop above leaves `blocks().size() == 0`, while
> calling the `Graph`-overload `dis.disassemble(bytes, 0x1000, graph)`
> against the same bytes produces `blocks().size() == 1`. If you want
> structure, call the `Graph`-overload — don't hand-roll it by looping
> `addInstruction()`.

## Mode 3 — a single block (`disassembleBlock`)

A third, narrower option: decode instructions starting at a given address
until a block terminator (return, trap, or jump) is hit, and return just
that block's instructions — no worklist, no CFG:

```cpp
auto blockInsns = dis.disassembleBlock(bytes, /*baseAddress=*/0x1000,
                                       /*startAddress=*/0x1000);
```

Useful when you already know a block's start address (e.g. from a prior
`analyze()` pass, or from your own symbol table) and just want its
instructions without re-running full analysis.

## `LINEAR_SWEEP` vs `RECURSIVE_TRAVERSAL`

`Configuration::disassemblyStrategy` controls how the flat listing (mode 1)
walks the byte buffer — it has no effect on mode 2's analysis pass, which
always follows the CFG regardless of this setting.

- **`LINEAR_SWEEP`** (default) — decodes sequentially from offset 0 to the
  end of the buffer, one instruction after another, with no awareness of
  control flow. Simple and complete for a buffer that's pure code, but it
  will happily "decode" embedded data, jump tables, or padding as if they
  were instructions, and can desynchronize (produce garbage) after any
  inline data blob.
- **`RECURSIVE_TRAVERSAL`** — starts a worklist at `baseAddress`, decodes
  until a terminator (return, or an unconditional/indirect jump with no
  resolved target), and pushes every direct branch target it discovers onto
  the worklist. This avoids disassembling data interleaved with code, but
  it only reaches code that's actually reachable from `baseAddress` through
  direct branches — a jump table or computed/indirect call target it can't
  resolve statically won't be explored.

```cpp
dragon::Configuration config;
config.disassemblyStrategy = dragon::DisassemblyStrategy::RECURSIVE_TRAVERSAL;

dragon::Disassembler dis(dragon::Architecture::X86_64, config);
auto instrs = dis.disassemble(bytes, 0x1000);  // now follows control flow
```

## The `Instruction` API

Every `Instruction`, from any of the three modes above, exposes:

**Decode-time fields** (always populated):

| Field | Type | Meaning |
|---|---|---|
| `address()` | `uint64_t` | Load address of the instruction's first byte |
| `size()` | `uint8_t` | Encoded length in bytes |
| `mnemonic()` | `string_view` | e.g. `"mov"`, `"b.le"` |
| `operands()` | `string_view` | e.g. `"rax, rbx"` |
| `disassembly()` | `string_view` | Full text: mnemonic + operands |
| `bytes()` | `vector<uint8_t>` | Raw encoded bytes |
| `pattern()` | `string_view` | Byte pattern with address-dependent bytes wildcarded |
| `chromosomeMask()` | `vector<uint8_t>` | Parallel to `bytes()`: `0x00` fixed, `0xFF` wildcard — for signature/pattern search |
| `branches()` | `set<uint64_t>` | Known direct branch targets (empty for indirect/non-branch) |
| `callees()` | `set<uint64_t>` | Known direct call targets |
| `edges()` | `size_t` | Outgoing CFG edges: 0 (fallthrough-only), 1 (unconditional branch), 2 (conditional) |
| `mcInst()` | `const llvm::MCInst*` | Raw LLVM instruction, or `nullptr` if decode failed — needs `InstructionImpl.hpp` |

**Classification flags** (always populated, from the decode itself):

| Flag | Meaning |
|---|---|
| `isReturn()` | `ret`, `bx lr`, ... |
| `isCall()` | `call`/`bl`, direct or indirect |
| `isJump()` | Any branch — calls are **not** jumps |
| `isConditional()` | e.g. `je`, `b.ne` |
| `isTrap()` | `ud2`, `hlt`, `int3`, `udf` |
| `hasIndirectTarget()` | Target isn't statically known, e.g. `jmp rax` |

**Structural flags** (only meaningful after mode 2's `analyze`/Graph-overload — always `false` from a flat listing):

| Flag | Meaning |
|---|---|
| `isBlockStart()` | First instruction of a basic block |
| `isFunctionStart()` | First instruction of a recognized function entry |
| `isPrologue()` | Part of a recognized function prologue (e.g. `push rbp`/`mov rbp, rsp`) |

{{< compare >}}
{{< pane lang="cpp" slot="first" >}}
for (const auto& insn : instrs) {
    if (insn.isCall())        std::cout << "call  -> ";
    if (insn.isJump())        std::cout << "jump  -> ";
    if (insn.isReturn())      std::cout << "ret\n";
    if (insn.isConditional()) std::cout << "(conditional)\n";

    for (uint64_t target : insn.branches())
        std::cout << "  branch -> 0x" << std::hex << target << "\n";
    for (uint64_t target : insn.callees())
        std::cout << "  callee -> 0x" << std::hex << target << "\n";
}
{{< /pane >}}
{{< pane lang="python" slot="second" >}}
def classify(insn):
    parts = []
    if insn.is_call: parts.append("call")
    if insn.is_jump: parts.append("conditional jump" if insn.is_conditional else "jump")
    if insn.is_return: parts.append("return")
    return " | ".join(parts)

for insn in graph.instructions():
    print(f"0x{insn.address:x}  {insn.mnemonic:<8} {insn.operands:<20} {classify(insn)}")
    for target in insn.branches:
        print(f"    branch target: 0x{target:x}")
{{< /pane >}}
{{< /compare >}}

## Disassembling the running example

Picking up the ARM64 bytes assembled in chapter 2 (`foo(x)`: returns `1` if
`x > 0`, else `-1`), run them through the full analysis path so the branch
and its target are resolved:

```python
import dragon

cfg = dragon.Configuration(syntax=dragon.Syntax.INTEL)
asm = dragon.Assembler(dragon.Architecture.ARM64, cfg)
raw = asm.assemble("""
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
""")

disasm = dragon.Disassembler(dragon.Architecture.ARM64, cfg)
graph = disasm.analyze(raw, 0x1000)

for insn in graph.instructions():
    tag = " (conditional branch)" if insn.is_conditional else ""
    branch = f"  -> resolved target: 0x{sorted(insn.branches)[0]:x}" if insn.branches else ""
    print(f"0x{insn.address:04x}  {insn.mnemonic:<6} {insn.operands}{tag}{branch}")
```

```text
0x1000  stp    x29, x30, [sp, #-16]!
0x1004  mov    x29, sp
0x1008  cmp    w0, #0
0x100c  b.le   #12 (conditional branch)  -> resolved target: 0x1018
0x1010  mov    w0, #1
0x1014  b      #8  -> resolved target: 0x101c
0x1018  mov    w0, #-1
0x101c  ldp    x29, x30, [sp], #16
0x1020  ret
```

> Note `operands()` prints the immediate exactly as LLVM's printer renders
> it — the raw ×4-scaled displacement (`#12`, `#8`), not a resolved address.
> The **resolved absolute target** is what `branches()` gives you, which is
> why the CFG/analysis code (and chapter 4's `BasicBlock::successors()`)
> reads from `branches()` rather than trying to parse `operands()`.

Chapter 4 picks up exactly here — `graph` above already has its blocks and
function recovered; we'll query them directly instead of re-disassembling.
