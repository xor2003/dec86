# Reko Borrow Execution Plan For Inertia

This plan turns the useful ideas from the local `reko/` tree into an ordered implementation program for Inertia.

The goal is not to imitate Reko mechanically.
The goal is to reproduce the highest-value ideas inside the angr/x86-16 pipeline in a way that improves:

- correctness
- stability
- decompilation speed
- source-like C
- eventual recompilability

## Current State

The core borrow architecture is already in place:

- centralized segment classification
- explicit alias-model boundary
- explicit widening boundary
- trait/evidence collection feeding narrow typed rewrites
- focused `snake` and `.COD` validation loops

This document now tracks only the work that still matters.

## Constraints

- Prefer repo-managed code over `.venv` hacks.
- Favor earlier recovery improvements over printer-only cleanup.
- Keep `ss`, `ds`, and `es` distinct until we can prove a safer collapse.
- Use real `.COD` and `examples/` functions as oracles after every meaningful change.

## Remaining Priority 1. Typed/Object Extensions

Goal:

- extend source-like object and typed rewrites only where evidence is stable

Primary targets:

- `ConfigCrts`
- `_MousePOS`
- `_SetHook`
- `_TIDShowRange`
- `rotate_pt`
- `_SetGear`
- `_ChangeWeather`

## Remaining Priority 2. Corpus-Driven Alias and Widening Extensions

Goal:

- extend the existing alias and widening boundaries only when real samples
  justify it

Primary targets:

- `_SetGear`
- `_InBox`-class predicates when a new regression appears
- `snake.EXE` guard and loop helpers
- new `.COD --proc` helpers that prove a clear source-like win

## Remaining Priority 3. Stability and Performance

Goal:

- keep the current wins stable and the focused runs cheap enough to stay in the
  inner loop

Primary targets:

- `snake.EXE:0x13b2`
- small `.COD --proc` helpers used in CLI tests

## Validation Strategy

At this point the main borrow architecture is in place. The remaining work is:

- keeping the current `snake` and `.COD` wins stable
- extending typed rewrites only when new samples justify them
- adding new corpus-backed widening or alias cases without broadening the
  current safe boundaries

After each meaningful change:

1. Run a narrow focused slice.
2. Recheck one `.COD` function and one real `.EXE` function manually.
3. Only expand scope if the narrow slice stays green.

Primary focused test slice:

- `tests/test_x86_16_cli.py -k 'sethook_branch_logic or setgear_guard_logic or rotate_pt_logic or tidshowrange_layout_logic or decompiles_snake_loop_function_instead_of_falling_back_to_asm'`

Then broader slices:

- `small_cod_logic_batch`
- sample-matrix block-lift tests
- selected `cod_samples` regressions

## Stop Conditions

Reassess the current approach if any of these happen repeatedly:

- the new classifier cannot stabilize `ss/ds/es` classification on real samples
- widening passes create more wrong code than they remove
- typed rewrites keep producing non-C-like pointer artifacts
- performance regresses on small functions despite caching and narrowing

## Immediate Next Steps

1. Keep the focused `snake` and `.COD` oracle slices green.
2. Add new typed/object rewrites only when a sample proves the same kind of
   source-like win as the current stable set.
3. Extend alias or widening only when a new corpus-backed case clearly needs
   it.
