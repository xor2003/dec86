# Inertia Decompiler

Inertia is an angr-based decompiler workspace focused on 16-bit x86 real-mode binaries.

Project priorities:

- correctness first
- readability second
- recompilable output where practical

## Optional native speedups (mypyc)

You can compile selected pure-Python modules with `mypyc` for native extension speedups while keeping source syntax unchanged.

1. Install optional dependency: `pip install ".[mypyc]"`
2. Run a module-focused build:

```bash
python scripts/build_mypyc.py build_ext --inplace
```

3. If compilation is not available, nothing changes; Python falls back to normal `.py` execution.

This repo is not aiming to be a source-shaped transpiler. When evidence is weak, it prefers explicit low-level C, visible assumptions, and honest fallback modes.

## Terminology / Glossary

### Core Architecture

The decompiler pipeline separates **execution semantics** (what the machine does) from **emitted C semantics** (what the output says). Internal representations carry low-level machine facts; later passes recover higher-level meaning and materialize it into C constructs. No machine-level artifact (e.g. `DS << 4`) may leak into final output unless explicitly chosen as a raw-emission mode.

### Execution Semantics

The low-level meaning of machine instructions during execution. In this decompiler, execution semantics are separated from emitted C semantics. Example: `DS << 4` may exist internally for real-mode execution, but must not leak into final C output.

### Semantic Recovery

The process of reconstructing higher-level program meaning from machine code: stack variables, loops, conditions, pointer types, function calls, structs/arrays. This happens *before* cosmetic rewrites.

### Materialization

The moment when an internal recovered semantic concept becomes an actual emitted C construct. Examples: stack slot `→` `local_2`, recurrence `→` `iRow++`, segmented access `→` `SEG_U16(ds, off)`. A semantic fact is not considered recovered until materialized into final emitted C.

### Canonicalization

Normalization of semantically equivalent expressions into a stable form. Examples: `x - 2 - 2 → x - 4`, `2892 + (i << 1) ↔ (i << 1) + 2892`. Canonicalization must not invent semantics.

### Tail Validation

Late-stage semantic comparison between the pre-postprocess representation and the final emitted representation. Used to ensure late rewrites did not corrupt semantics. Validation is strict: semantic drift = failure, unknown validation = failure, validation failure stops decompilation.

### Semantic Drift

A situation where recovered semantics change unexpectedly during later passes. Example: `iRow < nRows` becoming `iRow <= nRows` without proof. Semantic drift is treated as a pipeline error.

### Semantic Honesty

Principle that the decompiler must fail explicitly instead of emitting misleading C. Example: emitting `validation=failed` is acceptable; silently emitting wrong C is not acceptable.

### Segmented Memory Model

16-bit real-mode DOS memory model using segment registers (CS, DS, SS, ES) and offsets. Physical address: `(segment << 4) + offset`.

#### Segment Linearization

Conversion of segmented addresses into flat linear addresses. Example: `(ds << 4) + off`. Final emitted C must not expose raw linearization. Instead the decompiler emits `SEG_U16(ds, off)`, `SEG_PTR(ds, off)`, or `MK_FP(ds, off)`.

#### Laundered Segment Linearization

Illegal hidden form of segment linearization. Example: `tmp = ss; ptr = tmp << 4;` — even though `ss << 4` is not written literally, semantics are identical. Validation rejects such cases.

#### Runtime Helper

Portable helper abstraction replacing raw real-mode arithmetic. Examples: `SEG_U8(seg, off)`, `SEG_U16(seg, off)`, `SEG_PTR(seg, off)`, `MK_FP(seg, off)`. These preserve segmented-memory semantics without leaking implementation details.

### Stack Recovery

#### Stable Stack Slot

A stack location proven to represent a persistent local variable. Example: `SS:BP-0x2:size2` means stack segment, base pointer relative, offset -2, 2-byte variable.

#### Stack Carrier

Temporary low-level representation of a stack value before materialization. Examples: `s_0`, `s_4`, `s_fffd`. Carriers should disappear after proper materialization.

#### Byte Carrier

A temporary variable representing one byte of a wider stack/local value. Often appears in 16-bit arithmetic: `s_fffd = s_4 + 1 >> 8; s_4 += 1;`. Should eventually materialize into `iRow++`.

#### Widening

Combining smaller low-level pieces into a larger semantic value. Examples: low byte + high byte, segmented pointer pieces, split arithmetic carriers. Widening happens after alias proof.

#### Stack Alias

Proof that multiple expressions reference the same stack location. Examples: `*(&(&v1)[4])`, `SS:BP-0x2`, and `local_2` may all refer to the same variable.

#### Stack Canonicalization Bridge

Validation-only metadata proving that two different stack expressions represent the same stable slot. Used by tail validation to avoid false semantic differences.

#### Stack Lowering

Transformation from raw low-level stack expressions into higher-level C locals.

Example:

```c
*((ss << 4) + bp - 2)   →   local_2
```

### Control Flow / Conditions

#### ConditionIR

Intermediate representation for conditions and comparisons. Represents equality, ordering, signed/unsigned comparisons, and zero checks. Used to stabilize condition semantics before code generation.

#### Typed Condition Materialization

Conversion of low-level flag logic into typed C conditions.

Example:

```c
ZF == 0   →   x != 0
```

#### Condition Drift

Unexpected semantic mutation of a recovered condition during later passes. Detected by tail validation.

### Linear Recurrence

Recognized loop-update pattern.

Examples:

```c
i = i + 1    i += 1    i++
```

Or low-level carrier equivalents.

#### Recurrence Rebinding

Replacing low-level recurrence carriers with the already materialized semantic local.

Example:

```c
s_fffd = s_4 + 1 >> 8; s_4 += 1;   →   iRow++
```

### Callsite Recovery

#### Callsite Materialization

Recovery of actual function arguments from stack pushes and call setup patterns.

#### Stale Pushed Arguments

Arguments left over from previous stack state that incorrectly survive into recovered calls.

Example: `clock(45, 14)` for a zero-argument function.

#### Prototype Stabilization

Recovery and enforcement of consistent function signatures. Sources: recovered call usage, known helper signatures, COD source headers, annotations.

#### Honest Fallback Prototype

Safe fallback signature used when exact prototype recovery is impossible. Preferred over emitting invalid or misleading C.

### Validation / Pipeline

#### PipelineHardError

Fatal semantic pipeline error. Used when semantics are corrupted, validation fails, unresolved forbidden constructs remain, or materialization invariants fail. Stops decompilation immediately.

#### Rewrite Lane

Late-stage cosmetic transformation phase. Allowed: formatting, simplification, canonicalization. Forbidden: inventing semantics, changing recovered meaning, type inference.

#### Semantic Consumer

A pass that converts proven semantic facts into higher-level representations. Examples: stack lowering, recurrence materialization, prototype materialization.

#### Acceptance Gate

Final correctness gate requiring: generated C exists, validation passed, gcc syntax check passed, no unresolved semantic blockers.

#### Compile-Readiness

State where emitted C is syntactically valid and compilable.

Checked using:

```bash
gcc -std=c99 -Wall -Werror -fsyntax-only
```

#### Dead Setup Artifact

Low-level temporary emitted into final C even though semantic materialization already consumed it.

Example:

```c
vvar_23 = &s_6 + 2;
```

Such artifacts must be removed before emission.

#### Semantic Ownership

Rule defining which pipeline layer is responsible for a semantic transformation. Example: stack lowering owns stack-local recovery; rewrite does not own semantic recovery; validation does not repair semantics. Used heavily throughout AGENTS.md.

## Killer Features

- **Real-mode x86 support in angr**: in-tree `x86-16` arch, lifter, SimOS, DOS MZ loader, and DOS NE loader
- **Decompiler CLI that works on real DOS inputs**: whole-binary or single-function recovery from `.COM`, `.EXE`, raw blobs, and `.COD`
- **Sidecar-aware recovery**: `.COD`, `.LST`, `.MAP`, CodeView, and TDINFO metadata improve labels, ranges, and emitted C
- **Evidence-backed fallback modes**: timeouts and lift failures stay visible instead of being silently replaced with guessed output
- **Library signature support**: import `.pat`, OMF `.obj`, and OMF `.lib` into a deduplicated PAT catalog
- **Tail validation**: semantic checks on late pipeline output instead of trusting cleanup blindly
- **Batch corpus tooling**: decompile whole `.COD` trees into sibling `.dec` outputs with bounded workers and validation baselines
- **Integrated debugger utilities**: angr-backed DOS debugging through GDB RSP and a Textual TUI

## Supported inputs

### Executables and blobs

| Input | Status | Notes |
|---|---|---|
| `.COM` | supported | blob-loaded with DOS SimOS |
| `.EXE` DOS MZ | supported | in-tree loader with relocations |
| `.EXE` 16-bit NE | smoke-level supported | loaded through `dos_ne` backend |
| `.BIN` / `.RAW` | supported | blob loading |
| `.COD` | supported | can be loaded as a blob or sliced by `--proc` |

### Metadata and symbol sources

| Source | Usage |
|---|---|
| `.COD` listings | procedure slicing, local naming, source-backed annotations |
| `.LST` listings | labels, ranges, segment-aware metadata |
| `.MAP` files | code/data layout and public symbol recovery |
| CodeView NB00 / NB02 / NB04 | symbol/type/debug metadata when embedded |
| TDINFO | Borland/Turbo Debugger symbol metadata |
| `.pat` / OMF `.obj` / OMF `.lib` | library signature matching via deduplicated PAT catalogs |

## CLI

The main entrypoints are:

- `./decompile.py`
- `python -m inertia_decompiler.cli`
- installed script: `decompile-x86-16`

`decompile.py` re-execs into `./.venv/bin/python` when that virtualenv exists, so local runs stay on the repo interpreter by default.

Basic usage:

```bash
./decompile.py examples/snake.EXE
./decompile.py angr_platforms/x16_samples/ICOMDO.COM
./decompile.py examples/BENCHMUL.BIN --blob --base-addr 0x1000 --entry-point 0x1000
./decompile.py LIFE.EXE --addr 0x11423 --timeout 30
./decompile.py cod/DOSFUNC.COD --proc _dos_free --proc-kind NEAR --timeout 10
```

Current CLI options:

- `--addr` decompile one function by address
- `--blob` force blob loading
- `--base-addr` and `--entry-point` control blob/COM layout
- `--show-asm` print the first lifted block before C
- `--proc` and `--proc-kind` extract one procedure from a `.COD`
- `--timeout` bound analysis time
- `--window` bound CFG recovery near a target address
- `--max-memory-mb` set a best-effort address-space cap
- `--max-functions` cap whole-binary output volume
- `--api-style` choose helper naming style: `modern`, `dos`, `raw`, `pseudo`, `service`, `msc`, `compiler`
- `--pat-backend` choose PAT matcher backend: `hyperscan` or `python_regex`
- `--signature-catalog` load a deduplicated PAT catalog

## Output model

The x86-16 recovery pipeline is organized around:

`IR -> Alias model -> Widening -> Traits -> Types -> Rewrite`

Control-flow structuring and confidence/assumption reporting are explicit parts of the current pipeline, not late cosmetic cleanup.

When recovery fails or times out, the CLI reports that directly and may emit one of several evidence-backed fallbacks, including:

- partial-timeout C
- sidecar-slice C
- trivial sidecar C
- non-optimized fallback C
- assembly fallback
- lift-break probes

Tail-validation summaries are emitted for semantic guardrails instead of treating late-stage rewrites as automatically trusted.

## Install

The repo is tested against the angr stack pinned in [pyproject.toml](/home/xor/vextest/pyproject.toml).

Recommended local setup:

```bash
git submodule update --init --recursive
python3.11 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
python -m pip install -e ".[test]"
```

If you are working on the in-tree `angr_platforms` package directly, reinstall after submodule updates so the root environment and editable package stay aligned.

## Signature catalogs

To build one deduplicated PAT catalog from `.pat`, `.obj`, and `.lib` inputs:

```bash
python scripts/build_signature_catalog.py signature_catalogs/ QLINK/ --output signature_catalogs/local.pat
```

That catalog can then be used during decompilation:

```bash
./decompile.py your_binary.exe --signature-catalog signature_catalogs/local.pat
```

## Batch `.COD` runs

To decompile a whole `.COD` corpus into sibling `.dec` files:

```bash
python scripts/decompile_cod_dir.py cod --timeout 20 --max-memory-mb 1024
```

Useful filters:

- `--cod-file <name-or-path>` limit to one or more listings
- `--proc-name <name>` limit to one or more procedures
- `--skip-existing` avoid overwriting existing `.dec`
- `--write-tail-validation-baseline` persist the current changed-set baseline

## Sample corpus

The repo includes a small x86-16 corpus under [angr_platforms/x16_samples/README.md](/home/xor/vextest/angr_platforms/x16_samples/README.md).

Typical sample flow:

```bash
./angr_platforms/scripts/build_x16_samples.sh
./.venv/bin/python -m pytest -q angr_platforms/tests/test_x86_16_sample_matrix.py
./decompile.py angr_platforms/x16_samples/IMOD.EXE
./decompile.py angr_platforms/x16_samples/IMOD.COD --proc _main
```

## Debugging tools

The repo also carries debugger utilities built around angr simulation, GDB RSP, and Textual:

```bash
python -m inertia_decompiler.debug_dos LIFE.EXE --port 1234
python -m inertia_decompiler.gdb_tui --host 127.0.0.1 --port 1234 --arch x86_16
```

## Layout

Main code:

- [inertia_decompiler/cli.py](/home/xor/vextest/inertia_decompiler/cli.py): root decompiler CLI
- [inertia_decompiler/project_loading.py](/home/xor/vextest/inertia_decompiler/project_loading.py): loader selection, blob setup, packed-EXE handling
- [inertia_decompiler/sidecar_metadata.py](/home/xor/vextest/inertia_decompiler/sidecar_metadata.py): sidecar/debug metadata loading
- [inertia_decompiler/tail_validation.py](/home/xor/vextest/inertia_decompiler/tail_validation.py): validation routing and reporting
- [angr_platforms/angr_platforms/X86_16](/home/xor/vextest/angr_platforms/angr_platforms/X86_16): x86-16 platform, loaders, and analysis support

## Focused tests

Good starting points:

```bash
./.venv/bin/python -m pytest -q \
  angr_platforms/tests/test_x86_16_smoketest.py \
  angr_platforms/tests/test_x86_16_cli.py \
  angr_platforms/tests/test_x86_16_cod_samples.py \
  angr_platforms/tests/test_x86_16_dos_mz_loader.py \
  angr_platforms/tests/test_x86_16_dos_ne_loader.py \
  angr_platforms/tests/test_x86_16_sample_matrix.py \
  angr_platforms/tests/test_x86_16_tail_validation.py
```

For wider x86-16 coverage, the test suite also includes dedicated files for structuring, aliasing, widening, segmented memory, string instructions, recovery artifacts, helper modeling, confidence reporting, corpus scans, and validation manifests under [angr_platforms/tests](/home/xor/vextest/angr_platforms/tests).


  Use it like this:

  ./.venv/bin/python scripts/codex_resume_loop.py \
    --prompt "go on. fix function by function. Finish only when all functions are fixed." \
    --goal-cmd 'jq -e ".stop_reason==\"goals_met\"" angr_platforms/.cache/auto_decomp_loop/DONE.marker.json >/dev/null 2>&1' \
    --status-cmd 'test -f angr_platforms/.cache/auto_decomp_loop/DONE.marker.json' \
    --max-iterations 200 \
    --stagnation-limit 30

  Better default for your flow:

  - keep --last (default) so it resumes the same Codex session
  - use --goal-marker-file or --goal-cmd as hard stop marker
  - use --stop-file /tmp/STOP_CODEX_LOOP as emergency manual kill switch.
