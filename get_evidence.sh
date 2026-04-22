#!/usr/bin/bash
> result.txt; ls AGENTS.md inertia_decompiler/*.py angr_platforms/angr_platforms/X86_16/*.py  angr_platforms/angr_platforms/X86_16/*/*.py ./SORTDEMO.dec  | while read name; do echo "Filename $name:\n" >> result.txt; cat $name >> result.txt;done
