# Numeric Frame Offset Reproducer (2026-09-08)

## Minimal Binary

No external calls, source, sidecar, or library recognition is required:

```text
55 89 e5 83 ec 02 8d 46 fe a3 00 02 89 ec 5d c3
push bp
mov bp, sp
sub sp, 2
lea ax, [bp-2]
mov [0200h], ax
mov sp, bp
pop bp
ret
```

The eight instructions occupy 16 bytes. A direct angr/Inertia decompiler run
at address 0x1000 emits a host object reference into the scalar store, including
`g_200 = &v0` and `g_201 = &v0 >> 8`. This reproduces the numeric/host-pointer
projection problem without InitMenu's nested or indirect calls. The direct
analysis output is a diagnostic, not CLI acceptance; no successful compilation
or validation claim is made for it.

## Executable Behavioral Target

The regression in `test_x86_16_frame_prologue_carriers.py` executes the bytes
with SS=0x2000, DS=0x3000, saved BP=0x4000 and a return target of 0x1800.
Entry SP is parameterized over 0x1000, 0x0000 and 0x0001. The last case crosses
FFFFh while saving/restoring BP and protects the existing byte-safe frontend.

Every case requires:

- AX and the word at DS:0200 equal `(entry_sp - 4) & 0xffff`.
- SS:0200 remains untouched, keeping the address spaces distinct.
- BP returns to 0x4000; SP becomes `(entry_sp + 2) & 0xffff`; IP becomes 0x1800.

This is a frontend execution oracle, not proof that generated C matches it.
The test module is already selected by Make and the default test pipeline.
Combined frame and partial-GP checks: 12 passed, seven dependency warnings,
8.42s under `pytest -n 7`; all five slowest individual durations under one
second. Ruff `check --fix` and `git diff --check` pass.

## IR Boundary Evidence

The owned function-SSA regression follows the exact reaching definitions of
AX at 0x1006 through `scalar_definitions.py`. Its only live-in root is the
16-bit entry SP. Evaluating MOV/Add16/Sub16 along that path, masking each
result to 16 bits, produces `(entry_sp - 4) & 0xffff` for all three oracle
inputs. This checks arithmetic as well as provenance; merely finding the
expected constants would not detect reversed subtraction or a lost wrap.
The temporary identity takes precedence over incidental offset metadata;
the latter must not be added a second time.

The frame, partial-GP, and logical-write modules now report **22 passed**, seven
dependency warnings, in **8.84s**. Ruff `check --fix` and worktree
`git diff --check` pass. Evidence: `/tmp/inertia-frame-ir-numeric-tests.log`.

Installed angr's `analyses/s_propagator.py` replaces tracked SP/BP register
uses with `StackBaseOffset` expressions (around lines 454-487). An unchanged
live observer recorded 191 replacements, 19 distinct events, including entry
BP becoming `sp+0` at 0x1000, framed BP becoming `sp-2` at 0x1006, and AX
becoming `sp-4` at the scalar store at 0x1009. This confirms execution of the
candidate boundary. No installed dependency was modified. The existing Lowering
`stack_pointer_snapshot.py` handles saved pointer-argument versions, not
numeric entry-SP reconstruction, so it is not a drop-in repair here.

## Rejected Standalone Entry-BP Origin Filter

The tracker stores `OffsetVal(Register(BP), 0)` for incoming BP separately
from `OffsetVal(Register(SP), 0)` for incoming SP. Its `offset_before` API
returns only the offset, so propagation treated both as entry SP. That is
incorrect even before the numeric LEA result reaches host-object projection.

A trial in `stack_compat.py` removed propagated stack-register replacements
without proven entry-SP origin, preserving the original register expression.
It checked the full tracked value before existing width normalization.
**The trial was reverted:** it caused `add_sc` in MS C tiny `scalar_types_io`
to fail tail validation in both the batch and two direct retry attempts.
Do not repeat this standalone filter without addressing its downstream
frame/prologue consumers and demonstrating full DOS-pipeline acceptance.

- Reason: saving incoming BP must not save entry SP or a host-object address.
- DoD: refuse incoming-BP, unknown, bottom, and constant origins; retain a
  proven entry-SP origin; preserve original expressions and account for all
  refusals; pass scoped tools and default DOS gates. **Not met.**
- Definition of failure: assume equal offsets imply equal registers, delete
  the save, modify guest wrapping, or regress another accepted function.
- Focused regression before: four failed, nine passed in 8.08s. After:
  35 passed in 9.24s across stack compatibility, frame, GP, and logical-write
  tests. Seven dependency warnings; all five slowest tests under one second.
- Trial pipeline admission checks: 63 passed in 17.84s. Stack-compatibility tests
  were added to the default lane; Make and ownership selection already
  included them. This addition happened after the current lane had started.
- Scoped Ruff `check --fix`, MyPy, and venv Pyright passed. Global quality
  reported 29 MyPy diagnostics outside this trial; not a green quality gate.
- Broad trial result: 2,522 unit tests passed in 133.57s; QuickC passed;
  MS C tiny failed on `scalar_types_io/add_sc`. Two lanes passed, one failed.
  Evidence: `/tmp/inertia-stack-origin-rejected-pipeline.json` and
  `/tmp/inertia-stack-origin-pipeline.log`.

The failed `add_sc` payload exposes uninitialized byte reads at `SS:BP+1`
and `SS:BP+2` in the frame restore. It emits an incomplete BP assignment
containing `(...)`, which GCC also rejects. The reverted baseline emits only
`return b + a;` and passes validation. This localizes the trial's downstream
breakage to saved-frame restoration/projection, not the function's arithmetic.
Retained evidence: `/tmp/inertia-stack-origin-rejected-add-sc.c` and `.log`.
The next origin-preserving experiment must keep the save and restore coherent
or eliminate them together using a proven nonescaping balanced-frame effect;
retaining a numeric save alone is not sufficient. Do not repair this in C text
or suppress the uninitialized-read verdict.

The trial diagnostic saved `inertia_ebp & 0xffff` instead of a
host-object reference. Its numeric DS store remains pointer-valued and DCE
validation still rejects/restores changes. This is not accepted generated C
or InitMenu closure. After reverting only this trial, direct `add_sc` again
exits zero with `validation=passed` and clean whole-tail validation. Evidence:
`/tmp/inertia-stack-origin-reverted-add-sc.log`. No trial production code or
trial-only assertion is retained; existing user/agent edits are preserved.
The routine admission of existing stack compatibility tests is retained.
The next repair must preserve entry-SP provenance for
numeric consumers while retaining the object view for pointer consumers.

Measured work window: first live probe at 23:19 local, rejection and direct
baseline restoration verified by 23:30 local on 2026-09-08; about eleven
minutes including test waits, not a total-plan ETA. Logs use `/tmp/inertia-stack-origin-` with
`before`, `after`, `production`, `admission`, `quality`, and `pipeline` suffixes.

## Restored Checkpoint

After reverting the trial, the default pipeline passes all three lanes:
2,530 unit tests in 98.28s, QuickC, and all MS C tiny round trips. No failed,
skipped, or timed-out lanes. Lane wall times are 98.681s, 2.528s, and 26.401s;
these are warm-cache verification results, not a decompiler speedup claim.
The separately rerun retained stack-compatibility/admission tests pass 58
tests in 17.44s. Ruff `check --fix` and `git diff --check` pass.
Evidence: `/tmp/inertia-stack-origin-restored-pipeline.log`,
`/tmp/inertia-stack-origin-restored-admission.log`, and the pipeline summary.
Global MyPy remains at the previously measured 29 diagnostics; no full-suite
or remote CI closure is claimed. The temporary observer script was deleted.

## Repair Contract

- Reason: storing a LEA result numerically exposes the guest frame coordinate;
  a host C object's address cannot substitute for that observable value.
- DoD for the reproducer/oracle step: isolate the defect without external
  callees and verify the expected register, memory, frame, and wrap behavior.
  Met. Production repair remains open.
- DoD for the next repair: retain the original entry-SP/BP SSA provenance
  through the first pointer-valued projection, produce recompilable numeric C,
  and compare its execution against all three oracle cases. Then verify
  pointer consumers separately and rerun InitMenu's full acceptance contract.
- Definition of failure: guess entry SP, cast host addresses to guest integers,
  fold away the DS store, alter frontend wrapping, or use these passing machine
  tests to claim passing generated C.

Temporary evidence: `/tmp/inertia-numeric-frame-minimal.log` and
`/tmp/inertia-numeric-frame-oracle-tests.log`. No new production behavior or
full-suite/CI closure is claimed.

## Live SSA-To-Object Boundary (2026-09-09)

Rechecked on `29bc06e26`, without changing dependency or production files.
The installed angr SSA rewriting engine, not its C stack-offset handler,
performs the next relevant conversion:

```text
SPropagator: SP/BP use -> StackBaseOffset
SimEngineSSARewriting._handle_expr_StackBaseOffset:
    StackBaseOffset -> UnaryOp("Reference", stack VirtualVariable)
CStructuredCodeGenerator._handle_Expr_UnaryOp:
    Reference(stack VirtualVariable) -> CUnaryOp("Reference", local object)
```

Exact installed sources are under `angr/analyses/decompiler/`:
`ssailification/rewriting_engine.py:565` and
`structured_codegen/c.py:4317`. In this reproducer, an unchanged observer on
`CStructuredCodeGenerator._handle_Expr_StackBaseOffset` saw **zero calls**.
An observer on `_handle_Expr_UnaryOp` saw **22 Reference expressions**:
12 at stack offset -4, six at -2, two at -1, and two at zero. These are
observations from this input, not an exhaustive inventory of other binaries.

The two references originating at the LEA carry
`ins_addr=0x1006`, `vex_block_addr=0x1006`, `vex_stmt_idx=3`; their operand is
the same one-byte stack virtual variable at offset -4. The Reference itself
is **16 bits**, despite its one-byte referent. One reaches Store through
Convert; the other reaches BinaryOp then Convert for the upper byte.
The virtual-variable operand has no tags. Consequently:

- Patching only the C StackBaseOffset handler misses this live path.
- The reference's instruction provenance can link to the already-tested
  owned SSA definition. Do not infer the numeric value from the local's
  display name, referent width, or untagged operand.
- Preserve the original register base as well as displacement: the earlier
  incoming-BP versus entry-SP ambiguity still requires the paired-frame fix.
- `PTR_U16(&local)` is not that fix. The current portable-flat runtime macro
  casts through `uintptr_t` and truncates a host address; it does not supply
  guest entry SP. A runtime entry-state contract must justify numeric output.

The baseline and both observers emitted byte-identical declarations/body:
SHA-256 `8755f4259aa5324ff73ec48e58241872d22a7089877e57e84ace9a764cd89acf`.
The hash scope starts at `extern char g_1;`, excluding diagnostics and observer
records. Output remains invalid C, including the pointer-valued DS store and
upper-byte shift; this is not a semantic or compilation acceptance result.

Next implementation requirements, in dependency order:

1. Preserve a typed numeric entry-register definition through the SSA
   reference conversion, with Alias retaining the separate object identity.
   Reason: both views are observable. DoD: exact origin/width/provenance for
   both store bytes and saved/restored BP. Failure: treat offset zero as proof
   of entry SP, or repair rendered C.
2. Materialize numeric consumers from that definition and an explicit guest
   entry-state contract; retain object references for proven pointer consumers.
   Reason: portable host addresses are not guest stack coordinates. DoD:
   execute recompiled C for all three oracle inputs and pass the existing
   `add_sc` round trip. Failure: host-pointer truncation, guessed entry SP,
   unpaired frame removal, or lost memory/register effects.
3. Verify InitMenu, strict recompilation and whole-tail validation before
   calling the production defect fixed. Keep optimization deferred.

Evidence logs: `/tmp/inertia-frame-codegen-observer.log`,
`/tmp/inertia-frame-reference-observer.log`, and
`/tmp/inertia-frame-projection-boundary-tests.log`. Observers were scoped to
their diagnostic processes; no observer hook remains installed.
Focused frame-carrier, canonical-frame and setup-carrier checks pass:
**14 passed, seven dependency warnings, 8.69s**, using `pytest -n 7` with
`PYTHON_JIT=1`. All five reported slowest durations are below the configured
one-second display threshold. These tests protect existing machine/IR and
carrier behavior; they do not execute the invalid generated C. No Python
files changed in this investigation, so no new typing/lint closure is claimed.
