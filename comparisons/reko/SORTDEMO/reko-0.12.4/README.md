# Reko 0.12.4 SORTDEMO comparison artifact

This directory contains an unedited Reko decompilation of the project's
canonical `SORTDEMO.EXE` benchmark. It is comparison evidence only and is not
an input to Inertia's recovery or validation pipeline.

## Identity

- Reko: `0.12.4.0` (`git:aa02002c3b`)
- Reko release: <https://github.com/uxmal/reko/releases/tag/version-0.12.4>
- Package: `CmdLine-0.12.4-x64-aa02002c3b.zip`
- .NET runtime: `8.0.29`, Linux x64
- Input SHA-256: `0e809cfff4f7774d62b73c2fdf96da067bf143127c22cd0402ad7c3beb54151b`

## Main output

The generated high-level source is:

`SORTDEMO.reko/SORTDEMO_0800.c`

Its generated type declarations are in `SORTDEMO.reko/SORTDEMO.h`. The other
files are Reko's raw assembly, disassembly, and global-data artifacts and are
kept so the result can be audited rather than judging only rendered C.

## Reproduction

From the repository root, with the release unpacked at the path below:

```sh
/home/xor/.local/opt/dotnet-8/dotnet \
  /home/xor/.local/opt/reko-0.12.4/decompile.dll \
  decompile --time-limit 600 \
  comparisons/reko/SORTDEMO/reko-0.12.4/SORTDEMO.EXE
```

The recorded run completed successfully in 9.46 seconds with a maximum RSS of
119584 KiB.

## Known limitation of this run

Reko detected Microsoft C 8 and NB02 CodeView data, but version 0.12.4 could
not parse one old CodeView leaf type (`CodeView leaf type 0 00 not implemented
yet`). Reko continued and returned exit status 0, generating the files in
`SORTDEMO.reko/`. Consequently this is valid binary-driven Reko output, but it
must not be described as a complete debug-symbol-assisted decompilation.
