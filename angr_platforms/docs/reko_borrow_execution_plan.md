# Reko Borrow Execution Plan For Inertia

This plan turns the useful ideas from the local `reko/` tree into an ordered implementation program for Inertia.

The goal is not to imitate Reko mechanically.
The goal is to reproduce the highest-value ideas inside the angr/x86-16 pipeline in a way that improves:

- correctness
- stability
- decompilation speed
- source-like C
- eventual recompilability

## Current Progress

- Priority 1 is in place:
  - segment-space classification is centralized in `decompile.py`
  - `ss`/`ds`/`es` consumers now reuse the same cached classifier
- Priority 2 is partially in place:
  - byte-pair word load/store coalescing already consumes the classifier
  - small safe segmented byte-pointer rewrites now exist for `snake`-style `ds/es` byte access
- Priority 3 has groundwork in place:
  - access traits for repeated `base + const` and `base + index * stride` segmented accesses are now collected and cached per decompilation run
  - a real `.COD` proc test now verifies that segmented access traits are actually recorded in the cache
  - the cache now also keeps repeated-offset evidence for later field/array recovery
  - repeated-offset evidence now drives narrow field-like names for stable segmented data accesses when no source label exists
  - stack-side `ss + const` accesses now also rewrite to source-like pointer arithmetic instead of staying as raw real-mode segment math
  - field-like names are now width-unified when the same offset is seen as both byte and word access
  - register-only `ds` pointer arithmetic in `snake`-style helpers now drops raw `ds * 16` scaffolding too
  - `es` byte-pointer arithmetic in `snake`-style helpers now also loses raw `es * 16` scaffolding when the rest of the projection is safe
  - adjacent byte temporaries in `snake.EXE:0x1287` now collapse into a source-like word condition instead of `byte | byte * 0x100`
- Current concrete wins:
  - `snake.EXE:0x13b2` now decompiles without `...` and with byte-pointer access like `*((char *)v25)`
  - `snake.EXE:0x11d8` recovers listing-backed data labels such as `segmentcount` and `fruitactive`
  - `snake.EXE:0x135c` / `0x1387` now recover coordinate projection as `(v4 >> 8) * 160 + (v4 & 255) * 2`
  - `snake.EXE:0x135c` no longer prints `es * 16` in the `writecharat` byte-pointer write
  - `snake.EXE:0x1287` now keeps the source labels `field_0` and `field_1` while dropping raw `ds * 16` scaffolding
  - `snake.EXE:0x1287` now simplifies the guard to `if (!(field_0 & v17))`
  - `snake.EXE:0x1287` now simplifies the guard further to `if (!field_0)`
  - `.COD` helpers like `_rotate_pt`, `_SetGear`, and `_TIDShowRange` remain green under the focused CLI slice

## Constraints

- Prefer repo-managed code over `.venv` hacks.
- Favor earlier recovery improvements over printer-only cleanup.
- Keep `ss`, `ds`, and `es` distinct until we can prove a safer collapse.
- Use real `.COD` and `examples/` functions as oracles after every meaningful change.

## Priority 1. Segment-Space Classifier

Goal:

- replace repeated ad hoc matching of `seg * 16 + off` with one central classifier

What to implement:

- classify segmented accesses into:
  - `stack`
  - `global`
  - `extra`
  - `segment_const`
  - `unknown`
- keep a per-decompilation cache of classification results
- expose helpers that return both:
  - storage class
  - normalized address expression / offset / segment source

Expected payoff:

- fewer repeated tree walks
- safer downstream rewrites
- simpler `ss/ds/es` handling everywhere else

Primary targets:

- `_MousePOS`
- `_SetHook`
- `_TIDShowRange`
- `snake.EXE:0x13b2`

## Priority 2. Projection-Style Widening

Goal:

- generalize byte-pair and split-value recovery into one coherent family of passes

What to implement:

- adjacent byte load -> word load
- adjacent byte store -> word store
- split `segment` + `offset` uses -> one pointer-like value when stable
- small register-pair widening where it improves conditions or addresses

Expected payoff:

- less `low | high * 0x100`
- fewer duplicate store pairs
- smaller expression trees
- better chances of killing `...`

Primary targets:

- `_rotate_pt`
- `_TIDShowRange`
- `_ChangeWeather`
- `snake.EXE:0x13b2`

## Priority 3. Access-Trait Collection

Goal:

- infer field/array evidence from normalized addresses instead of guessing late
- use repeated-offset evidence to name stable segmented data accesses when no source label is available

What to implement:

- detect `base + const`
- detect `base + index * stride + const`
- detect repeated loads/stores at same offsets
- detect simple table accesses under `ds` / `es`

Expected payoff:

- move from pointer arithmetic to fields and arrays
- enable later type recovery with stronger evidence

Primary targets:

- cockpit UI helpers
- `rotate_pt`
- `ConfigCrts`
- `show_summary` and `fold_values` matrix functions

## Priority 4. Alias-Aware Value Recovery

Goal:

- reduce wrong conditions and noisy temporaries caused by split register/value modeling

What to implement:

- lightweight storage-domain reasoning for:
  - subregisters
  - flag groups
  - word values rebuilt from byte defs
- synthesize alias-like rewrites only when they unblock real recovery

Expected payoff:

- cleaner branch conditions
- fewer false temporaries
- better guard reconstruction

Primary targets:

- `_InBox`-class predicate code
- `_SetGear`
- `snake.EXE` loop and guard logic

## Priority 5. Typed Rewrite To Source-Like Memory Objects

Goal:

- once accesses are classified and widened, rewrite them to locals/globals/member access

What to implement:

- `ss:frameoff` -> stack local / argument
- `ds:const` -> global variable or named field
- `segconst:const` -> segment-owned object / table member
- preserve `es` as a separate pointer space unless a stronger proof appears

Expected payoff:

- fewer raw `seg * 16 + off`
- more recompilable C
- clearer declarations

Primary targets:

- `_SetHook`
- `_SetDLC`
- `_MousePOS`
- `_ChangeWeather`
- `_TIDShowRange`

## Priority 6. Type Evidence Layer

Goal:

- recover enough type shape to improve recompilability without inventing too much

What to implement:

- width propagation from widened loads/stores
- char/word distinction for globals and locals
- simple pointer/member-pointer recognition
- array element width/stride hints

Expected payoff:

- fewer bogus `char` declarations
- cleaner function locals
- stronger follow-on rewrites

Primary targets:

- `_SetGear`
- `_ChangeWeather`
- `_rotate_pt`
- `fold_values`

## Priority 7. Performance Tightening

Goal:

- keep small functions under a practical decompilation budget

What to implement:

- cache hot classifier/matcher results
- reduce repeated whole-tree passes
- stop running expensive rewrites when the function shape makes them impossible
- bias to bounded function windows and early body-only extraction when safe

Expected payoff:

- keep small functions near the 5-second target
- reduce variance on `snake` and small `.COD` helpers

Primary targets:

- `snake.EXE:0x13b2`
- small `.COD --proc` helpers used in CLI tests

## Validation Strategy

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

1. Extend the new byte-pointer rewrite only to other safe zero-offset base-register cases.
2. Add more focused `snake`-family oracles so new source-like pointer output stays locked in.
3. Start collecting lightweight access traits for repeated `base + const` uses under `ds/es`.
4. Recheck:
   - `writecharat`
   - `readcharat`
   - `_TIDShowRange`
   - `_rotate_pt`
   - `_SetGear`
   - `snake.EXE:0x13b2`
