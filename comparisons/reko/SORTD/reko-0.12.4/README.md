# Reko 0.12.4 SORTD comparison artifact

This directory contains an unedited Reko decompilation of the project's
sidecar-free `SORTD.EXE` benchmark. It is peer-decompiler comparison evidence
only and is not an input to Inertia's recovery or validation pipeline.

## Identity

- Reko: `0.12.4.0` (`git:aa02002c3b`)
- Reko release: <https://github.com/uxmal/reko/releases/tag/version-0.12.4>
- Package: `CmdLine-0.12.4-x64-aa02002c3b.zip`
- .NET runtime: `8.0.29`, Linux x64
- Input SHA-256: `3a8263c0f35ac5cf56a8e3664a0d505415aab8ca6e3a15fcebb14af9ac473640`

## Main output

The generated high-level source is:

`SORTD.reko/SORTD_0800.c`

Its generated type declarations are in `SORTD.reko/SORTD.h`. Reko also emitted
raw assembly, disassembly, globals, and segment artifacts; these are retained
so the result can be audited beyond the rendered C.

Reko emitted 161 procedure comments. This is whole-program discovery including
compiler/runtime code and must not be compared directly with Inertia's scoped
20 non-library application functions.

## Reproduction

From the repository root, with the release unpacked at the path below:

```sh
/home/xor/.local/opt/dotnet-8/dotnet \
  /home/xor/.local/opt/reko-0.12.4/decompile.dll \
  decompile --time-limit 600 \
  comparisons/reko/SORTD/reko-0.12.4/SORTD.EXE
```

The recorded run returned exit status 0 in 8.96 seconds with a maximum RSS of
115968 KiB.

## Comparison with the debug-bearing SORTDEMO run

`SORTD.EXE` and `SORTDEMO.EXE` have identical bytes through offset 26431; the
next byte is where they diverge because `SORTDEMO.EXE` carries appended debug
information. Reko's generated code and type declarations are identical except
for the input-derived filenames and include name. Its code-segment assembly and
disassembly outputs are byte-identical.

This shows that Reko 0.12.4 did not gain useful recovery information from the
NB02 CodeView payload in `SORTDEMO.EXE`; its C for stripped `SORTD.EXE` has the
same unresolved `<invalid>` and `<unknown>` constructs and is not directly
recompilable.
