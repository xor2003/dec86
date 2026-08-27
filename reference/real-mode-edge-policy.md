# Practical real-mode edge-case policy

Model semantics plausibly used by already-unpacked real DOS programs written in C or straightforward assembly without expanding IR to reproduce processor bus behavior or synthetic boundary probes.

The current input contract is unpacked executable code with stable analyzed code bytes. Ordinary compiler output, hand-written assembly, simple optimization or obfuscation idioms, and assembly compatibility tricks that work around processor limitations or documented generation differences are in scope. Runtime packers, encrypted or polymorphic bodies, heavily mutated control flow, anti-debugging, undocumented bus or timing probes, and self-modifying decode loops are outside the current scope. Self-modifying code may be supported later through an explicit code-write and invalidation model.

## In scope

- Ordinary unaligned accesses.
- 16-bit and 32-bit effective-address arithmetic used in real mode.
- Realistic near and far control transfers.
- Ordinary far-pointer objects fully contained inside a segment.
- Divide errors.
- SALC.
- Straightforward assembly workarounds for processor limitations, errata, or documented generation differences.

Host-page boundaries are execution artifacts, not architectural exclusions. Fix the execution or verifier memory model rather than excluding them.

## Excluded

- Architecturally undefined results.
- Segment-limit violations and partial-fault side effects.
- Multi-byte operands or far-pointer objects deliberately straddling the 64 KiB end of a segment.
- Prefetch, open-bus, and bus-cycle behavior.
- Pathological self-overlapping `ENTER` frame chains.
- Synthetic register and memory states whose only purpose is exposing processor bus or microcode ordering.
- Behaviors currently required only by packed, encrypted, polymorphic, heavily mutated, anti-debugging, processor-probing, or self-modifying code.

## IR and verification rules

- Do not globally split normal word or dword operations into byte IR solely for rare boundary behavior.
- Prefer normal typed wide IR and repair the execution bridge.
- Use explicit byte operations only where architectural segmented wrapping is itself in scope.
- Keep exclusions typed and reason-coded in verification reports.
- Never silently turn an unsupported edge into a pass.
