# x86-16 Example Matrix

This table tracks the real `.COD` / `.COM` / `.EXE` examples we are actively
using as decompiler-quality and logic-correctness oracles for Inertia
decompiler.

The intent is practical:
- keep a small set of named examples visible
- show which ones are tiny and cheap versus large and noisy
- record what each example is currently useful for

## Focused Examples

| Example | Proc | Kind | File Size | Current Logic Anchor | Notes |
| --- | --- | --- | ---: | --- | --- |
| `cod/default/MAX.COD` | `_max` | near | `2771` B | `if (x > y) return x; return y;` | Smallest branch/return correctness case. Also checks `.COD --proc` skipping of leading `__chkstk`. |
| `cod/f14/NHORZ.COD` | `_ChangeWeather` | near | `108285` B | direct truth-test plus `8150`, `500`, `125`, `1000` | Good for direct-memory compare recovery and `if/else` shape. |
| `cod/f14/MONOPRIN.COD` | `_mset_pos` | near | `20309` B | `% 80`, `% 25` | Good for simple arithmetic and frame-wrapper normalization. |
| `cod/f14/BILLASM.COD` | `_MousePOS` | near | `5689` B | `if (!MOUSE) return 0;`, `x * 2` | Good for byte compare recovery and tiny early-return logic. |
| `cod/f14/BILLASM.COD` | `_rotate_pt` | near | `5689` B | indexed word loads, `a1 * -1`, trig-call setup | Good for small arithmetic/setup logic before call-heavy code. |
| `cod/f14/PLANES3.COD` | `_Ready5` | near | `637819` B | `46`, `18`, `return` | Large source file, but the chosen procedure is still small and good for struct-stride anchoring. |
| `cod/f14/COCKPIT.COD` | `_LookDown` | near | `354631` B | `50`, `27`, `25`, `39` | Good for constant-heavy branch bodies and repeated field updates. |
| `cod/f14/COCKPIT.COD` | `_LookUp` | near | `354631` B | `150`, `138`, `136`, `139` | Pairs with `_LookDown`; same shape, different constants and else-path. |
| `cod/f14/COCKPIT.COD` | `_ConfigCrts` | near | `354631` B | counted copy loop, `flag * 2`, `546 + v5`, `flag < 8` | Good for simple loop/copy correctness on a real large `.COD` source file. |
| `cod/f14/CARR.COD` | `_InBox` | near | `254653` B | `return 1;`, relational comparisons | Good for multi-condition bounds logic. Still somewhat low-level, but stable. |
| `angr_platforms/x16_samples/ICOMDO.COM` | `_start` | tiny `.COM` | n/a in this table | `get_dos_version(); print_dos_string(...); exit(0);` | Best user-facing tiny runtime sample. More about helper-call quality than arithmetic logic. |
| `angr_platforms/x16_samples/ISOD.EXE` | `_start` | small-model `.EXE` | paired with `ISOD.COD` | named DOS helpers plus startup constants | Useful bridge from tiny examples to real startup code. Still noisier than the small `.COD` set. |

## `fold_values` Matrix

These are the same source-level arithmetic helper across different memory-model
and optimization variants from the sample matrix.

| Example | Proc Kind | File Size | Current Logic Anchor | Notes |
| --- | --- | ---: | --- | --- |
| `angr_platforms/x16_samples/ISOD.COD` | near | `8527` B | `123`, `return` | Small model, `/Od` style baseline. |
| `angr_platforms/x16_samples/ISOT.COD` | near | `7596` B | `123`, `return` | Small model optimized variant. |
| `angr_platforms/x16_samples/ISOX.COD` | near | `7596` B | `123`, `return` | Small model alternate optimized build. |
| `angr_platforms/x16_samples/IMOD.COD` | far | `8676` B | `123`, `return` | Medium model baseline; useful for far-model decompilation correctness. |
| `angr_platforms/x16_samples/IMOT.COD` | far | `7760` B | `123`, `return` | Medium model optimized variant. |
| `angr_platforms/x16_samples/IMOX.COD` | far | `7760` B | `123`, `return` | Medium model alternate optimized build. |
| `angr_platforms/x16_samples/IHOD.COD` | far | `9006` B | `123`, `return` | Huge model baseline. |
| `angr_platforms/x16_samples/IHOT.COD` | far | `8042` B | `123`, `return` | Huge model optimized variant. |
| `angr_platforms/x16_samples/ILOD.COD` | far | `9006` B | `123`, `return` | Large model baseline. |
| `angr_platforms/x16_samples/ILOT.COD` | far | `8042` B | `123`, `return` | Large model optimized variant. |

## `show_summary` Matrix

These are the same source-level summary-print wrapper across the 10 sample
matrix variants. Today it is useful in two ways:
- decompiled-C consistency for split word-load reconstruction
- block-lift consistency for near/far `cprintf` call setup

| Example | Proc Kind | File Size | Current Logic Anchor | Notes |
| --- | --- | ---: | --- | --- |
| `angr_platforms/x16_samples/ISOD.COD` | near | `8527` B | three `g_info` pushes + format push before `_cprintf` | Small model `/Od` baseline. |
| `angr_platforms/x16_samples/ISOT.COD` | near | `7596` B | three `g_info` pushes + format push before `_cprintf` | Small model optimized variant. |
| `angr_platforms/x16_samples/ISOX.COD` | near | `7596` B | three `g_info` pushes + format push before `_cprintf` | Small model alternate optimized build. |
| `angr_platforms/x16_samples/IMOD.COD` | far | `8676` B | three `g_info` pushes + format push before far `_cprintf` | Medium model baseline. |
| `angr_platforms/x16_samples/IMOT.COD` | far | `7760` B | three `g_info` pushes + format push before far `_cprintf` | Medium model optimized variant. |
| `angr_platforms/x16_samples/IMOX.COD` | far | `7760` B | three `g_info` pushes + format push before far `_cprintf` | Medium model alternate optimized build. |
| `angr_platforms/x16_samples/IHOD.COD` | far | `9006` B | `push ds` + format pointer + far `_cprintf` setup | Huge model baseline. |
| `angr_platforms/x16_samples/IHOT.COD` | far | `8042` B | `push ds` + format pointer + far `_cprintf` setup | Huge model optimized variant. |
| `angr_platforms/x16_samples/ILOD.COD` | far | `9006` B | `push ds` + format pointer + far `_cprintf` setup | Large model baseline. |
| `angr_platforms/x16_samples/ILOT.COD` | far | `8042` B | `push ds` + format pointer + far `_cprintf` setup | Large model optimized variant. |

## `_main` Matrix

These are the same source-level `main` wrapper across the 10 sample matrix
variants. Today it is useful as a decompiled-C consistency ladder for call
sequence stability and folded-byte/word value flow around the final
`fold_values(...)` return path.

| Example | Proc Kind | File Size | Current Logic Anchor | Notes |
| --- | --- | ---: | --- | --- |
| `angr_platforms/x16_samples/ISOD.COD` | near | `8527` B | `_main`, helper calls, `& 0xff00 |`, final return call | Small model `/Od` baseline. |
| `angr_platforms/x16_samples/ISOT.COD` | near | `7596` B | `_main`, helper calls, `& 0xff00 |`, final return call | Small model optimized variant. |
| `angr_platforms/x16_samples/ISOX.COD` | near | `7596` B | `_main`, helper calls, `& 0xff00 |`, final return call | Small model alternate optimized build. |
| `angr_platforms/x16_samples/IMOD.COD` | far | `8676` B | `_main`, helper calls, `& 0xff00 |`, final return call | Medium model baseline. |
| `angr_platforms/x16_samples/IMOT.COD` | far | `7760` B | `_main`, helper calls, `& 0xff00 |`, final return call | Medium model optimized variant. |
| `angr_platforms/x16_samples/IMOX.COD` | far | `7760` B | `_main`, helper calls, `& 0xff00 |`, final return call | Medium model alternate optimized build. |
| `angr_platforms/x16_samples/IHOD.COD` | far | `9006` B | `_main`, helper calls, `& 0xff00 |`, final return call | Huge model baseline. |
| `angr_platforms/x16_samples/IHOT.COD` | far | `8042` B | `_main`, helper calls, `& 0xff00 |`, final return call | Huge model optimized variant. |
| `angr_platforms/x16_samples/ILOD.COD` | far | `9006` B | `_main`, helper calls, `& 0xff00 |`, final return call | Large model baseline. |
| `angr_platforms/x16_samples/ILOT.COD` | far | `8042` B | `_main`, helper calls, `& 0xff00 |`, final return call | Large model optimized variant. |

## Current Use

- The focused example set is the main small-to-medium logic correctness ladder.
- The `fold_values` matrix is the current model/optimization consistency ladder.
- The `show_summary` matrix is the current decompiled-C consistency ladder for
  split word-load reconstruction across memory models and optimization levels.
- The `show_summary` matrix also now has a block-lift ladder for the `_cprintf`
  call-setup prefix, which is a cleaner oracle for near/far ABI differences.
- The `_main` matrix is the current decompiled-C consistency ladder for helper
  call ordering and folded byte/word flow across the same 10 variants.
- The `query_interrupts` setup prefix is now also locked across all 10 sample-matrix variants at block-lift level:
  - `ISOD`, `ISOT`, `ISOX`
  - `IMOD`, `IMOT`, `IMOX`
  - `IHOD`, `IHOT`
  - `ILOD`, `ILOT`
- A second `query_interrupts` matrix now also locks the `int86x(0x21)` / `g_info.int21_segment` / `g_info.int21_offset` tail across those same 10 variants.
- That matrix is intentionally block-level today because it is a cleaner correctness oracle than the current full decompiled C for those startup/helper-heavy routines.
- When adding new examples, prefer:
  - one small, source-obvious procedure
  - one clear logic anchor
  - one reason the example is distinct from the ones already here
