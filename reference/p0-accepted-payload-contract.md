# Read-Only Accepted Payload Contract

## Checkpoint (2026-09-07)

The payload verifier protocol declared three writable fields, although the
actual `FunctionWorkResult` is frozen and the verifier only reads them. This
caused four `cli_core.py` MyPy errors. The protocol now declares read-only
properties for payload, validation hash, and compiler-check hash.

- Reason: acceptance verification consumes immutable evidence; it must not
  require permission to rewrite the payload or its proof hashes.
- DoD: the real frozen result satisfies the contract without casts; valid
  evidence passes; missing and mismatched proofs still reject; verification
  does not modify results; import isolation, tests, docs, and scoped typing pass.
- Definition of failure: making the result mutable, weakening hash checks,
  adding suppressions, or substituting a fake mutable result for production.

Before: the exact production-result-to-verifier call failed MyPy because all
three fields were read-only. Five existing tests passed in 8.66s. After:
eight tests passed in 8.88s, including real immutable-result acceptance and
missing-proof refusal. Scoped Ruff `check --fix`, MyPy, and Pyright pass.
MyPy also passes on `cli_core.py` with imported-module diagnostics silenced
using `--follow-imports=silent`; this is not a global typing pass.

No generated-C or decompiler-layer behavior was changed. The prior default
pipeline result remains historical evidence, not a rerun after this typing
change. Global MyPy, full-suite, remote CI, and the LEA repair remain open.
Startup architecture, agent-context, and test-ownership checks also passed;
Understand-Anything automatic updates remain disabled.

Logs: `/tmp/inertia-accepted-contract-mypy-before.log`,
`/tmp/inertia-accepted-contract-after.log`,
`/tmp/inertia-accepted-contract-cli-mypy.log`, and
`/tmp/inertia-accepted-contract-pyright.log`.
