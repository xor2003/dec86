# InitMenu Nested-Call Boundary (2026-09-08)

## Latest Numeric-Frame Investigation

After the tail-origin inventory repair, the normal sidecar-free InitMenu
regression still fails (33.97s including test overhead). A worker observation
run reports `validation_failed` after 19.98s: Structuring and Postprocess
live-out stages remain stable, but GCC rejects pointer operands to `&`.
Both accepted-payload and GCC-checked hashes remain absent. Stable tail
summaries therefore do not establish accepted or recompilable output.

The numeric GP owner already supports BP/SP (`inertia_ebp`/`inertia_esp`),
including low-word views. The missing piece is not another runtime symbol.
`prune_frame_prologue_stack_assignments_8616` consumes canonical frame
instruction carriers as effects represented by a C function. Its source alone
does not prove it caused the missing numeric initialization in this function.

An observation-only wrapper installed on the Lowering owner and its
Structuring import initially produced no visible stderr records, including an
in-process-profile attempt. That was an observation-channel gap, not proof
that the callback was absent. A local import check
confirmed the short and long real-mode module names refer to the same module,
so duplicate module objects were not the cause. The direct CLI captures both
streams into `debug_output`; the clean-worker result branch returns before
printing it. A file-backed observational sink resolves this gap, as below.

### Verified Pass Boundary

The file-backed run recorded 11 invocations for function 0x10060. The first
returned changed and removed these tagged entry assignments:

- At 0x10060: a casted stack slot receives a casted reference to the BP+0
  stack anchor; another assignment carries its high byte.
- At 0x10061: physical register offset 20, width 2 (BP), receives a casted
  reference to the BP-2 stack anchor.
- The ten subsequent invocations returned unchanged with no entry assignments.

Thus the frame definition is already pointer-valued at the input to frame
pruning. Merely retaining that assignment does not recover a numeric guest
offset. A correct repair must preserve or reconstruct the original numeric
frame definition from authoritative IR/SSA before conflating it with the C
object view; pruning must subsequently respect any retained numeric obligation.

The observed worker took 20.97s and remained `validation_failed`, with no
accepted/GCC hash. Its rejected C was byte-identical to the preceding worker,
SHA-256 `42b035a5ea947d2193c069fc0d35c24df77499af1eb77371c0a7ce7eb962fb9e`.
This checks observer transparency, not semantic acceptance. The observations
are diagnostic-only; addresses are not production matching rules.

Evidence: `/tmp/inertia-frame-numeric-observations.jsonl` and
`/tmp/inertia-frame-numeric-file-worker.json`. The temporary probe source was
removed. For future direct-worker probes, use an independent observation sink
or explicitly retrieve captured debug output; silence on stderr is not evidence
that a pass was not executed.

The next implementation must preserve two distinct projections of the same
Alias-derived stack location:

1. A host C object/address view for proven pointer arguments and local access.
2. A numeric guest offset for LEA values that remain live in registers. Its
   base must derive from an exact entry/frame SP/BP SSA definition, with
   prologue, width/wrap, and teardown obligations retained when observable.

Reason: a host address is not a 16-bit guest offset. DoD: first establish
coverage of the actual execution path producing the rejected LEA expression;
then preserve the numeric frame definition and its typed consumers across
IR/Alias/Lowering, with scalar and pointer uses tested separately. The existing
four-site compilation, call-preservation and whole-tail acceptance contract
below remains mandatory. Definition of failure: invent a BP initialization,
cast a host pointer to satisfy GCC, drop a live frame effect, or claim an
unobserved pass explains the failure. The frame-pruning observation boundary
is now covered; the next boundary is the first producer of its pointer-valued
BP definition, before inventing any runtime initialization or changing DCE.

Temporary evidence: `/tmp/inertia-initmenu-current.log`,
`/tmp/inertia-frame-numeric-run3.log`, `/tmp/inertia-frame-numeric-worker3.json`.
No production code changed in this investigation; no new full-suite or global
quality result is claimed. The temporary observer source was removed.

## Binary Evidence

Direct Capstone16 decoding of SORTD.EXE's load image (MZ header 176 bytes,
load base 0x10000) extends the previous prefix investigation:

1. Text output at 0x12756 calls 0x12e1a before writing AX.
2. 0x12e1a immediately calls 0x15390.
3. 0x15390 compares memory at 0x638 with 0xd6d6. One conditional path returns;
   another executes PUSH CS and a near CALL to 0x10f90.
4. 0x10f90 saves BX, sets BX to 0xffff, then executes an indirect near CALL
   through memory at 0x63a. No preceding instruction in this chain writes AX.
   Its epilogue restores BX and uses RETF, so naive near-call stack traversal
   would also be insufficient.
5. Another text-output callee, 0x12efb, writes AH=2 and executes INT 10h.
   Writing AH does not prove incoming AL dead. Interrupt-specific typed input
   evidence is required to establish whether AL is observed.

These addresses identify observations, never production recovery rules. The
indirect target and conditional memory values have not been resolved. This
does not prove AX is consumed; it proves that the proposed simple traversal
cannot establish that it is not consumed.

## Architectural Consequence

The existing IR status-flag binary CFG adapter uses project.factory.block and
a six-status-bit semantic domain. It is not a drop-in late-Lowering GP-register
proof: it would introduce lifting side effects and still require authoritative
indirect-call and interrupt effects. Do not reinterpret its status bits as AX.

Do not implement a recursive prefix scanner merely to bypass the first CALL.
First inspect existing target/effect evidence for the indirect boundary. If
unknown remains, preserve the numeric register value and investigate its
invalid stack-address C representation at the typed address/lowering owner.
A cast from a host C pointer to an integer is not a real-mode address proof.

## Next Task Contract

- Reason: InitMenu must emit valid, semantically equivalent C even when a
  register setup cannot be proven dead.
- DoD: close the retained numeric-address representation or obtain complete
  binary-derived target/effect evidence; all four sites compile, whole-tail
  validation passes, required calls and value/pointer argument classes survive,
  and the normal sidecar-free worker publishes matching validation/GCC hashes.
- Definition of Failure: assuming a benign library/stack-check name, skipping
  conditional paths, treating an unknown indirect call or interrupt as no-input,
  ignoring the near-call/PUSH-CS/RETF convention, or deleting to satisfy gcc.

Regression coverage in test_x86_16_register_entry_overwrite.py now exercises
the composed setup proof across direct calls, indirect near/far calls and
interrupts, both with all AX bits live and with only AL live. A later XOR AX,AX
must not justify deletion across an earlier unproven boundary.

InitMenu remains unaccepted. No production semantics changed in this checkpoint.

Verification: both register-entry and consumed-setup test modules pass with
`PYTHON_JIT=1 PYTHONHASHSEED=0`, pytest `-n 7`: **62 passed, 7 dependency
deprecation warnings in 9.24s**; the five slowest individual durations were
each below one second. Ruff `check --fix` and `git diff --check` pass.
The full suite and global quality gates were not rerun for this test/document
change; their previously recorded failures remain open.

## Numeric-State And Collector Follow-Up

Inspection of the recorded rejected InitMenu payload confirms it publishes
EAX but contains no numeric BP initialization. Replacing the remaining host
address anchor with a runtime EBP variable alone would therefore introduce an
unproven value. The earlier InitBars IR investigation already located the
original numeric BP-relative expression; preserve both the numeric and object
views and their initialization obligations when implementing this repair.

The callee range-fact collector also passed an optional canonical target into
integer-only indexes and facts. It now refuses an unresolved target in both
collection paths. This closes two scoped MyPy errors without casts or ABI
assumptions. A boundary-injection test fails before the repair; it covers both
unresolved and valid targets. The current canonicalizer returns an integer
for valid integer input, so this is contract hardening, not evidence of a
previously observed SORTD runtime failure.

Related collection/count/context tests: **22 passed, 7 dependency warnings in
10.17s**, pytest `-n 7`; the five slowest durations were each below one second.
Scoped Ruff `check --fix` and MyPy pass. InitMenu acceptance and full-project
quality closure remain open; no updated global diagnostic count is claimed.

## Subsequent IR Contract And Global Gate

Indexed-access normalization now explicitly checks that every grouped micro-op
has the same known instruction address. Its caller already filters missing
addresses; this closes the lost type invariant rather than claiming a live
missing-address crash. Numeric conversions of optional addresses are removed.
Existing word-copy regression coverage now also checks missing and mixed sites.
All 16 indexed-copy tests pass in 11.82s with seven dependency warnings; scoped
Ruff, MyPy and Pyright pass. No frontend byte-wrap methods were changed.

The refreshed `quality-fast` gate exits 2 with **94 MyPy diagnostic lines**,
down from the preceding 99. Both range-target diagnostics and all three
normalization diagnostics are absent. Compiled import smoke passes 39 modules.
Full log: `/tmp/inertia-ir-site-quality.log`. This is not a passing global gate,
a fresh full-suite census, or InitMenu acceptance.
