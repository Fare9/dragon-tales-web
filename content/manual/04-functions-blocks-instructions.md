---
title: "Functions, Basic Blocks and Instructions"
weight: 4
summary: "Recovering structure from a flat instruction stream"
---

Chapter 3 ended with a fully analyzed `Graph` — the ARM64 `foo(x)` example
disassembled via `analyze()` (Python) / the `Graph`-overload of
`disassemble()` (C++), with blocks and functions already recovered. This
chapter is about querying that structure: `Graph`, `Function`, and
`BasicBlock`, and how they relate to each other and to `Instruction`.

## The ownership model: `Graph` owns, everything else views

`Graph` is the only object that **owns** anything — it holds the full
instruction listing (`std::map<uint64_t, Instruction>`) and the sets of
addresses that analysis determined are valid block/function starts.
`BasicBlock` and `Function` are lightweight **views**: each is constructed
from a `const Graph*` and a start address, and internally walks the graph's
listing to answer questions. They don't copy instructions; they hold
pointers into the graph they were built from.

Practically, this means:

- A `BasicBlock`/`Function` is only valid as long as the `Graph` it points into is alive.
- Constructing one is cheap and side-effect-free — `dragon::BasicBlock(&graph, addr)` doesn't mutate `graph`.
- If the address you pass isn't a start address analysis actually recorded, you get back an object with `isValid() == false`, not an exception or null.

```cpp
dragon::BasicBlock bb(&graph, 0x1000);
if (!bb.isValid()) { /* 0x1000 isn't a known block start in this graph */ }
```

## `Graph`: the container and its query helpers

Beyond `blocks()`/`functions()` (chapter 3) and `get(address)` (instruction
lookup), `Graph` exposes the raw validity sets that `BasicBlock`/`Function`
construction checks against:

{{< compare >}}
{{< pane lang="cpp" slot="first" >}}
bool valid = graph.isValidBlock(0x1000);
bool validFn = graph.isValidFunction(0x1000);

const std::set<std::uint64_t>& blockStarts = graph.validBlockAddresses();
const std::set<std::uint64_t>& fnStarts    = graph.validFunctionAddresses();
{{< /pane >}}
{{< pane lang="python" slot="second" >}}
print(graph.block_addresses())     # every recovered block start
print(graph.function_addresses())  # every recovered function start
{{< /pane >}}
{{< /compare >}}

## `BasicBlock`

A `BasicBlock` is the span of instructions from a start address to the next
terminator (a branch, return, or trap — or the last instruction before
another block's start, if control simply falls through).

| Member | Meaning |
|---|---|
| `isValid()` | `false` if `startAddress` isn't a known block start, or the block is non-contiguous |
| `startAddress()` | First instruction's address |
| `terminatorAddress()` | Last instruction's address (**not necessarily a branch** — see below) |
| `instructions()` | `vector<const Instruction*>`, start to terminator inclusive |
| `get(address)` | Look up one instruction within this block |
| `terminator()` | Pointer to the terminator instruction |
| `size()` / `byteSize()` / `empty()` | Instruction count / total encoded bytes / emptiness |
| `successors()` | CFG successor addresses — **cached** after first call |
| `predecessors()` | CFG predecessor addresses — **cached**, **C++ only**, not exposed in the Python/C API |
| `clearCache()` | Drop the cached successors/predecessors (e.g. after mutating the graph) |

> **`terminatorAddress()` is not always a branch.** A block ends either at
> an actual control-flow instruction (branch/return/trap) *or* simply
> because the next instruction happens to be another block's start (e.g.
> it's a jump target from somewhere else, forcing a split even though
> control falls through to it). `successors()` accounts for both cases —
> it returns the branch targets for a real terminator, or the single
> fallthrough address for a split-but-not-branching block. Don't assume
> `terminator()->isJump()` is true; check `successors()` instead if what
> you actually want is "where does control go from here."

{{< compare >}}
{{< pane lang="cpp" slot="first" >}}
for (const dragon::BasicBlock& block : graph.blocks()) {
    std::cout << "block @ 0x" << std::hex << block.startAddress()
              << " (" << block.size() << " instrs, " << block.byteSize() << " bytes)\n";
    for (uint64_t succ : block.successors())
        std::cout << "  -> 0x" << succ << "\n";
}
{{< /pane >}}
{{< pane lang="python" slot="second" >}}
for addr in graph.block_addresses():
    block = graph.get_block(addr)
    print(f"block 0x{addr:x}  ({block.size} instrs, {block.byte_size} bytes)")
    for succ in block.successors():
        print(f"  -> 0x{succ:x}")
{{< /pane >}}
{{< /compare >}}

## `Function`

A `Function` is a BFS over blocks starting from an entry point, following
`successors()` until no new blocks are reachable — so it's exactly "every
block reachable from this entry," which for well-formed code is the whole
function body.

| Member | Meaning |
|---|---|
| `isValid()` | `false` if the address isn't a known function start, or it has no blocks |
| `startAddress()` | Entry point address |
| `blocks()` | `map<uint64_t, BasicBlock>`, keyed by block start address |
| `block(address)` | Look up one block by address |
| `instructions()` | Every instruction across every block, in address order |
| `numBlocks()` / `numInstructions()` / `byteSize()` | Counts and total size |
| `edges()` | Sum of each block terminator's `Instruction::edges()` — **only counts actual branch edges**, not fallthrough (see below) |
| `cyclomaticComplexity()` | `edges() - numBlocks() + 2` (the standard McCabe formula) |

> **`edges()` undercounts fallthrough-only blocks.** It sums each block's
> *terminator instruction's* `edges()` field — 2 for a conditional branch, 1
> for an unconditional branch, and **0** for anything else, including a
> `ret` or a block that ends purely because the next address happens to be
> another block's start. This matters for `cyclomaticComplexity()`: it's
> computed from this same `edges()`, so a function built entirely from
> fallthrough splits (no actual branches) can report a lower complexity
> than "number of paths through the CFG" would suggest. Verified against
> the running example below.

## Querying the running example

Continuing directly from chapter 3's `graph` (the ARM64 `foo(x)` analysis) —
no need to redisassemble:

```python
fn = graph.get_function(0x1000)
print("valid:", fn.is_valid)
print("blocks:", fn.num_blocks)
print("instructions:", fn.num_instructions)
print("bytes:", fn.byte_size)
print("cyclomatic complexity:", fn.cyclomatic_complexity)

for addr in fn.block_addresses():
    block = graph.get_block(addr)
    print(f"\nblock 0x{addr:x}  (terminator @ 0x{block.terminator_address:x})")
    for insn in block.instructions():
        print(f"    0x{insn.address:x}  {insn.mnemonic} {insn.operands}")
    print("  successors:", [hex(s) for s in block.successors()])
```

Actual output:

```text
valid: True
blocks: 4
instructions: 9
bytes: 36
cyclomatic complexity: 1

block 0x1000  (terminator @ 0x100c)
    0x1000  stp x29, x30, [sp, #-16]!
    0x1004  mov x29, sp
    0x1008  cmp w0, #0
    0x100c  b.le #12
  successors: ['0x1010', '0x1018']

block 0x1010  (terminator @ 0x1014)
    0x1010  mov w0, #1
    0x1014  b #8
  successors: ['0x101c']

block 0x1018  (terminator @ 0x1018)
    0x1018  mov w0, #-1
  successors: ['0x101c']

block 0x101c  (terminator @ 0x1020)
    0x101c  ldp x29, x30, [sp], #16
    0x1020  ret
  successors: []
```

This is a good illustration of the fallthrough case above: block `0x1018`'s
terminator is `mov w0, #-1` — not a branch at all — yet it still has a
resolved successor (`0x101c`), because that block was forced to end there
by `end_branch:` being a jump target from block `0x1010`. Walking through
`edges()`: block `0x1000`'s terminator (`b.le`, conditional) contributes 2;
block `0x1010`'s terminator (`b`, unconditional) contributes 1; blocks
`0x1018` and `0x101c` (terminators `mov` and `ret`, neither a branch)
contribute 0 each. Total `edges() == 3`, `numBlocks() == 4`, so
`cyclomaticComplexity() == 3 - 4 + 2 == 1`.

## Where this fits in the pipeline

`Function` and `BasicBlock` are the structures the rest of dragon-tales
builds on:

- Chapter 5's IGNIL lifter operates **per-block** — `graph.getIGNILBlock(startAddress)` returns the lifted IL for exactly one `BasicBlock`'s worth of code.
- Chapter 6's LLVM lifter takes a whole `Function` and lifts every block in it, using `successors()` to wire up LLVM basic block terminators.
- The backward slicer (see the `docs/cpp_api.md` reference and [IDEAS.md](https://github.com/Fare9/dragon-tales/blob/main/docs/manual/IDEAS.md)) walks blocks via `predecessors()`.
