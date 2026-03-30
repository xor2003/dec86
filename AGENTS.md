# Inertia Decompiler

## Overview

Project name: **Inertia decompiler**.

Decompiler for 16-bit x86 real mode based on angr.
angr_platforms - patched to support x86 16-bit.
angr_platforms/angr_platforms/X86_16 helps to convert x86 16-bit binary into AIL IR, and use angr as decompiler.
.venv/ have patched "angr" to support x86 16-bit which need to be moved upstream.

The `angr-platforms` project is a collection of AIL lifters that enhance the [angr](https://angr.io) binary analysis framework. These agents enable support for non-standard architectures, virtual machines, and esoteric languages by providing modular implementations of key angr subsystems:

- **Architecture (Arch)**: Defines register layouts, bit widths, endianness, and other hardware characteristics using [archinfo](https://github.com/angr/archinfo).
- **Loader**: Handles binary loading and memory mapping via [CLE](https://github.com/angr/cle) backends, supporting formats like ELF, raw blobs, or custom structures.
- **Lifter**: Translates machine code or instructions to VEX IR, allowing symbolic execution with angr's default engine.
- **Simulation Engine (SimEngine)**: Executes code symbolically, either via VEX (SimEngineVEX) or custom engines for direct interpretation.
- **SimOS**: Emulates operating system behaviors, including syscalls and high-level abstractions like file I/O, using angr's SimOS framework.

These agents are registered automatically upon import, integrating seamlessly with angr's lifecycle: loading → architecture identification → lifting → execution → OS simulation. For detailed internals, see the [tutorial](angr_platforms/tutorial/1_basics.md).

**Note**: Many platforms are better served by angr's pcode engine ([pypcode](https://github.com/angr/pypcode)). This repo receives limited maintenance; consider pcode for production use.

## Supported Platforms

The following platforms are supported, each with dedicated agents. Platforms marked [WIP] are works-in-progress.

### x86-16 (Real Mode)
- **Description**: Support for 16-bit x86 real mode decompiler.
- **Key Agents**:
  - Arch: [`arch_86_16.py`](angr_platforms/angr_platforms/X86_16/arch_86_16.py)
  - Lifter: [`lift_86_16.py`](angr_platforms/angr_platforms/X86_16/lift_86_16.py)
  - Core: [`emulator.py`](angr_platforms/angr_platforms/X86_16/emulator.py), [`processor.py`](angr_platforms/angr_platforms/X86_16/processor.py)
  - Instructions: [`instr_base.py`](angr_platforms/angr_platforms/X86_16/instr_base.py), [`instr16.py`](angr_platforms/angr_platforms/X86_16/instr16.py)
  - SimOS: [`simos_86_16.py`](angr_platforms/angr_platforms/X86_16/simos_86_16.py)
  - Hardware: Modules for memory ([memory.py](angr_platforms/angr_platforms/X86_16/memory.py)), I/O ([io.py](angr_platforms/angr_platforms/X86_16/io.py)), interrupts ([interrupt.py](angr_platforms/angr_platforms/X86_16/interrupt.py)).
- **Tests**: [`tests/test_x86_16bit.py`](angr_platforms/tests/test_x86_16bit.py)

#### AIL IR Lifting
Recent improvements include IRSB generation in [`lift_86_16.py`](angr_platforms/angr_platforms/X86_16/lift_86_16.py), instr16.py.

The AIL lifter supports a segment model for 16-bit real mode, handling CS shifts (<<4) for memory addressing in Load/Store operations. Use the existing lifter in /home/xor/vextest/angr_platforms/angr_platforms/X86_16 for decompilation without Capstone fallback.

**Verification**: Tested with raw bytes for MOV AX,1; ADD AX,2; RET (`b'\xb8\x01\x00\x05\x02\x00\xc3'`), loaded via blob backend. Produces correct pseudocode:  
```
AX = 1;
AX += 2;
return;
```
No external patched angr is needed for these basics; custom agents enable decompilation.

**Usage Example**:
```python
import angr

# Raw bytes example
binary = b'\xb8\x01\x00\x05\x02\x00\xc3'  # MOV AX,1; ADD AX,2; RET
p = angr.Project(binary, backend='blob', arch='X86_16')
cfg = p.analyses.CFG()
decomp = p.analyses.Decompiler(target_addr=0x0)
print(decomp.code)
```

## Usage

Install via `setup.py` ([setup.py](angr_platforms/setup.py), requires angr, cle, archinfo, pyvex). Import modules to register agents, then use angr as usual:

```python
import angr
p = angr.Project("path/to/binary")  # Auto-selects agents based on format/arch
```

## Global Goal

- This project is **not** aiming to become a transpiler.
- The goal here is an **angr-based decompiler** for 16/32-bit x86 real-mode binaries that produces **human-readable C**.
- Prefer building on angr's existing pipeline:
  - CFG recovery
  - VEX/AIL lifting
  - decompiler passes
  - structured C generation
- The main strategy is to make the decompiler better and faster by improving recovery quality before code generation, especially for:
  - control-flow structuring
  - variable and stack recovery
  - calling convention recovery
  - expression simplification
  - type recovery
  - naming and readability
- Priorities, in order:
  - improve human-readable C for the target corpus
  - preserve correctness while improving readability
  - make a useful subset of output recompilable where practical
- When forced to choose, favor decompiler-quality work over transpiler-style semantic re-expression.

### Architecture Model

Use this decompiler architecture as the default mental model:

`IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`

In practice:

- `IR` is the normalized input layer produced by lifting.
- `Alias model` decides which values really refer to the same storage.
- `Widening` combines byte-pairs, projections, and joins into cleaner values.
- `Traits` collect repeated-offset, stride, and induction evidence.
- `Types` turn stable evidence into arrays, structs, and typed pointers.
- `Rewrite` is the last-stage C cleanup layer that applies only after the
  evidence is stable.

The intended order is important: alias + widening first, then traits and types,
and only then object rewriting. Avoid mixing those layers together in a single
local pass if a boundary object or helper can keep the responsibilities clear.

For x86-16 specifically, model aliasing as:

- a `domain` that says what storage the value belongs to
- a `view` that says which slice of that storage is visible
- a `state` object that records whether a full value must be synthesized

Start with register domains, stack-slot domains, and segmented-memory domains.
Only widen values after the alias model has already proved that the parts are
compatible.

### Dream Decompiler Target

The long-term target for Inertia is an angr-based decompiler that recovers
readable, evidence-driven C from a real 16-bit x86 DOS corpus.

Keep the architecture mental model as:

`IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`

The detailed implementation roadmap lives here:

- `angr_platforms/docs/dream_decompiler_execution_plan.md`

Use that document for phase-by-phase planning, priorities, and concrete
deliverables. Keep this file focused on stable navigation and project rules.

### Operating Rules

#### Mission

Inertia is an angr-based decompiler for 16/32-bit x86 real-mode binaries.
The goal is human-readable, evidence-driven C, not a transpiler and not a bag
of output-specific hacks. Prioritize decompiler quality, correctness, and
maintainability over short-term cosmetic wins.

#### Core architecture rule

All changes must respect this pipeline:

`IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`

Mandatory interpretation:

- `IR` is the normalized input layer.
- `Alias model` decides storage identity.
- `Widening` combines proven-compatible narrow pieces into wider values.
- `Traits` collect evidence only.
- `Types` interpret stable evidence.
- `Rewrite` is a late cleanup layer only.

Hard rule:

- Do not solve an earlier-layer problem in a later layer just because it is convenient.
- Do not solve aliasing in final C rewrite.
- Do not solve widening by guessing from final expression shape alone.
- Do not guess structs or arrays before stable evidence exists.
- Do not let traits directly rewrite objects.

#### Direction-of-travel rule

A change is on the good path if it:

- explains existing wins with a more general architectural layer
- reduces one-off special cases
- improves multiple corpus cases with one mechanism
- keeps conservative behavior when evidence is weak

A change is on the wrong path if it:

- fixes one output by adding another special rewrite
- adds a new allowlist without first trying alias, widening, or evidence
- makes output prettier by guessing unsupported semantics
- hides architectural debt inside postprocess cleanup

Before merging a fix, explicitly ask:

- Is this solving the problem at the correct layer, or only hiding it later?

#### Correctness over prettiness

If evidence is weak, prefer:

- ugly but honest output
- explicit segmented arithmetic
- explicit temporaries
- conservative types

Do not prefer:

- guessed structs
- guessed arrays
- guessed helper signatures
- guessed pointer lowering
- guessed high-level logic

When uncertain, stay conservative instead of hallucinating.

#### Alias-first rule

Before adding any rule that joins, rewrites, or simplifies values, ask whether
it is really an alias problem.

Required behavior:

- Storage identity must come from the alias model.
- Register slices, stack slots, and segmented memory must be treated as
  storage with domain, view, and state.

Forbidden shortcuts:

- Do not join AL/AH/AX relationships only by expression shape.
- Do not treat two adjacent stack bytes as one word unless alias compatibility
  says so.
- Do not collapse segmented memory to pointer-like form before stable
  association is proven.

#### Widening must be proven, not guessed

Widening is allowed only after alias compatibility is established.

Every widening rule must have:

- candidate extraction
- compatibility proof
- rewrite

A widening change must document:

- which domain(s) it works on
- which views it joins
- what invalidates the join
- what tests prove it safe

Forbidden patterns:

- shape-only widening in late C text
- unconditional byte-pair folding
- widening that ignores clobber or versioning
- widening that crosses segment-space boundaries without proof

#### Traits are evidence, not conclusions

Trait collection must only produce evidence:

- repeated offsets
- stride
- induction
- array-like patterns
- member-like patterns

Traits may:

- annotate
- score
- classify
- produce profiles

Traits may not:

- directly invent structs
- directly invent arrays
- directly rename things as members unless downstream accepts the evidence

#### Type/object recovery must be downstream

Required order:

`alias facts -> widening -> evidence profiles -> type/object decision -> late rewrite`

Forbidden shortcuts:

- no early struct guessing
- no early array guessing
- no pointer-like lowering from raw convenience
- no member naming as a substitute for true object recovery

#### Segmented-memory discipline

Real-mode segmented memory is not one flat pointer world.

Required behavior:

- treat `ss`, `ds`, and `es` as distinct spaces
- distinguish stable base association from over-associated cases
- allow pointer/object lowering only when evidence is strong

Forbidden behavior:

- do not flatten all segmented accesses into one generic pointer model
- do not assume a segmented expression is object-like just because it looks familiar
- do not merge segment spaces for convenience

#### Rewrite layer restrictions

Late rewrite exists only for final cleanup.

Rewrite is allowed to do:

- tiny algebraic cleanup
- boolean normalization
- declaration cleanup
- naming polish
- final structured C cleanup

Rewrite must not do:

- core alias reasoning
- core widening reasoning
- storage identity
- object inference
- prototype inference

If a rewrite needs hidden storage knowledge to be safe, it belongs earlier.

#### Corpus-first engineering rule

All important changes must be justified against the real target corpus.

Required workflow:

- use bounded scan-safe corpus runs
- use focused regression cases
- use golden readability anchors
- use sample-matrix and existing x86-16 tests

Before merging a nontrivial change, check:

- did it help at least one real corpus case?
- did it regress any golden case?
- did it increase crashes or timeouts?
- did it reduce or increase special-case logic?

#### Scan-safe lane must remain conservative

Required behavior:

- scan-safe mode favors robustness over prettiness
- risky beautification must not be enabled by default in scan-safe runs
- every crash or timeout must remain classifiable

Forbidden behavior:

- do not put experimental quality passes into scan-safe by default
- do not trade robustness for one pretty output example

#### One-off rescue policy

Special rewrites, allowlists, and source-backed rescues are allowed only under
strict conditions.

Allowed only if:

- they protect an important real corpus case
- they are clearly labeled as temporary rescue, oracle-backed checkpoint, or narrow guard
- they do not block replacement by a general architectural layer

Required follow-up:

- replace by alias/widening/types architecture
- keep only as a regression oracle
- remove

Forbidden behavior:

- no silent growth of special-case registries
- no "just one more rewrite" without first checking alias, widening, traits, or types

#### Testing rules

Every change must add or update the smallest useful test at the correct level.

Prefer this order:

- unit test for the new rule or layer
- focused corpus-backed test
- scan-safe sanity confirmation

Required for architecture changes:

- alias behavior -> add unit tests on domains, views, and state
- widening -> add allowed and forbidden join tests
- segmented association -> add stable vs over-associated tests
- object or type recovery -> add evidence-driven corpus tests

#### File and responsibility discipline

Keep modules small and single-purpose.

Required behavior:

- new logic should go into focused modules
- avoid growing giant mixed-responsibility files
- if a file mixes multiple layers, split it

Preferred structure:

- alias
- widening
- traits
- types
- rewrite
- scan-safe orchestration

#### What to do before implementing a fix

Before writing code, classify the bug:

- Is this a lifting or runtime correctness bug?
- Is this CFG or call-recovery?
- Is this alias or storage identity?
- Is this widening or projection?
- Is this evidence, type, or object recovery?
- Is this only final readability polish?

Then implement it at the earliest correct layer.

#### What agents must never do

- Never add a rewrite that guesses semantics just to match source.
- Never move logic later in the pipeline because it is easier.
- Never add a corpus-specific hack without documenting why a general rule is not yet possible.
- Never weaken scan-safe robustness to improve one pretty example.
- Never confuse naming improvement with true recovery.
- Never collapse segmented memory into flat pointers by default.
- Never treat temporary source-backed rescue as proof that the architecture is finished.

#### Merge checklist for agents

Before finalizing a change, confirm:

- The fix is at the correct architectural layer.
- It does not violate `IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`.
- It improves or protects real corpus behavior.
- It keeps conservative behavior under uncertainty.
- It does not increase hidden special-case debt.
- It includes tests at the right level.
- It does not make scan-safe mode less stable.

#### Success criterion

Judge progress using this rule:

- Bad direction: every new good example needs another special rewrite, allowlist, or rescue
- Good direction: each new architectural layer explains more old wins, reduces special cases, and transfers to new corpus cases with less extra work

## Tutorials

- [Part 1: Basics](angr_platforms/tutorial/1_basics.md) – angr lifecycle and components.
- Subsequent parts cover arch, loader, lifter, engine, SimOS, and analysis.

## Contributing

Add new agents by implementing and registering classes (e.g., subclass `Arch`, `CLEBackend`, `Lifter`, `SimEngine`, `SimOS`). See [BrainFuck](angr_platforms/angr_platforms/bf/) as an example. WIP branches for incomplete platforms.

For issues or maintenance, consider angr's pcode alternatives.

## Repository Coding Guidelines

- **Files:** Keep individual source files under 300 lines where practical to improve reviewability and maintainability.
- **Single Responsibility Principle:** Prefer small modules/functions that do one thing. If a file grows beyond its focused purpose, split it into smaller files following SRP.
- **Why:** Smaller, SRP-aligned files simplify testing, linting, and code review for this project which targets low-level lifters and simulation helpers.


## Current x86-16 Status

Current x86-16 work is tracked in the dedicated docs and tests listed below.

Key docs:

- `angr_platforms/docs/x86_16_80286_real_mode_coverage.md`
- `angr_platforms/docs/x86_16_mnemonic_coverage.md`
- `angr_platforms/docs/x86_16_reference_priority.md`
- `angr_platforms/docs/dream_decompiler_execution_plan.md`

Key tests:

- `angr_platforms/tests/test_x86_16_smoketest.py`
- `angr_platforms/tests/test_x86_16_cod_samples.py`
- `angr_platforms/tests/test_x86_16_dos_mz_loader.py`
- `angr_platforms/tests/test_x86_16_sample_matrix.py`
- `angr_platforms/tests/test_x86_16_runtime_samples.py`
- `angr_platforms/tests/test_x86_16_compare_semantics.py`
- `angr_platforms/tests/test_x86_16_cli.py`

Current bounded focused test command:

```bash
../.venv/bin/python -m pytest -q \
  tests/test_x86_16_smoketest.py \
  tests/test_x86_16_cod_samples.py \
  tests/test_x86_16_dos_mz_loader.py \
  tests/test_x86_16_sample_matrix.py \
  tests/test_x86_16_runtime_samples.py
```

For corpus triage, prefer the bounded scanner:

```bash
../.venv/bin/python scripts/scan_cod_dir.py /path/to/cod_dir --mode scan-safe --timeout-sec 5 --max-memory-mb 1024
```

### Focused lint/type-check scope

- `pyproject.toml` now targets `ruff` and `mypy` primarily at:
  - `angr_platforms/X86_16/*.py`
  - the `tests/test_x86_16*.py` files
  - `tests/conftest.py`
- This is intentional: it keeps lint/type work centered on the x86-16 lifter/decompiler surface we are actively enhancing instead of the whole historical repo.
- Current local nuance:
  - the repo `.venv` still does not have `ruff` or `mypy` installed, so `../.venv/bin/python -m ruff ...` and `../.venv/bin/python -m mypy` currently fail with `No module named ...`

### Current x86-16 Status

Current work is tracked in the dedicated docs and tests above.

The main repo-managed areas to use are:

- `angr_platforms/docs/x86_16_80286_real_mode_coverage.md`
- `angr_platforms/docs/x86_16_mnemonic_coverage.md`
- `angr_platforms/docs/x86_16_reference_priority.md`
- `angr_platforms/docs/dream_decompiler_execution_plan.md`
- `angr_platforms/tests/test_x86_16_smoketest.py`
- `angr_platforms/tests/test_x86_16_cod_samples.py`
- `angr_platforms/tests/test_x86_16_dos_mz_loader.py`
- `angr_platforms/tests/test_x86_16_sample_matrix.py`
- `angr_platforms/tests/test_x86_16_runtime_samples.py`
- `angr_platforms/tests/test_x86_16_compare_semantics.py`
- `angr_platforms/tests/test_x86_16_cli.py`

Useful commands:

```bash
cd /home/xor/vextest/angr_platforms && ../.venv/bin/python scripts/scan_cod_dir.py ../cod --mode scan-safe --timeout-sec 5 --max-memory-mb 1024
cd /home/xor/vextest/angr_platforms && ../.venv/bin/python -m pytest -q tests/test_x86_16_smoketest.py tests/test_x86_16_cod_samples.py tests/test_x86_16_dos_mz_loader.py tests/test_x86_16_sample_matrix.py tests/test_x86_16_runtime_samples.py
```

For day-to-day x86-16 work, prefer small corpus-backed changes, keep the
scan-safe lane conservative, and use the dedicated docs for current progress
instead of duplicating history here.
