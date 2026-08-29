# SORTD application-function comparison

This report compares the 20 sidecar-free application functions in the
historical `SORTD.dec` transcript with the corresponding address-based Reko
0.12.4 output and the original implementations in `SORTDEMO.C`.

The source names are comparison labels only. They are not recovery evidence.
Reko's 161-procedure whole-program count includes compiler/runtime code and is
therefore not comparable to Inertia's intentionally scoped 20 functions.

## Address map

| Source function | Inertia body | Reko entry |
| --- | --- | --- |
| `main` | `0x10010` | `0800:0010` |
| `InitMenu` | `0x10060` | `0800:005D` |
| `DrawFrame` | `0x101F0` | `0800:01DB` |
| `RunMenu` | `0x102E0` | `0800:02CC` |
| `DrawTime` | `0x10498` | `0800:0491` |
| `InitBars` | `0x10560` | `0800:0554` |
| `ReInitBars` | `0x10678` | `0800:0672` |
| `DrawBar` | `0x106C8` | `0800:06C8` |
| `SwapBars` | `0x10768` | `0800:075B` |
| `Swaps` | `0x107B8` | `0800:0794` |
| `InsertionSort` | `0x10808` | `0800:07E7` |
| `BubbleSort` | `0x108D0` | `0800:08C0` |
| `HeapSort` | `0x10970` | `0800:095B` |
| `PercolateUp` | `0x109E8` | `0800:09E8` |
| `PercolateDown` | `0x10A88` | `0800:0A61` |
| `ExchangeSort` | `0x10B50` | `0800:0B2C` |
| `ShellSort` | `0x10C18` | `0800:0BF4` |
| `QuickSort` | `0x10CE0` | `0800:0CD4` |
| `Beep` | `0x10E70` | `0800:0E5D` |
| `Sleep` | `0x10F38` | `0800:0F18` |

Inertia uses canonical body entries after leading NOP padding. Reko uses the
earlier procedure entries, which is why several offsets differ.

## Per-function result

| Function | Historical `SORTD.dec` | Reko 0.12.4 compared with source |
| --- | --- | --- |
| `main` | Passed validation; clear application call sequence | Finds the same calls, but retains register plumbing and an `<invalid>` stack value |
| `InitMenu` | Passed; recognizable menu logic and calls | Recognizable branches and loop, but stack/register expressions obscure arguments and include `<invalid>` state |
| `DrawFrame` | Passed; all four parameters and 80-byte local buffer recovered | Recovers loops and frame operations, but exposes only three stack arguments and leaves a call-position value unresolved |
| `RunMenu` | Passed; clear switch and all application calls | Finds the menu dispatch and calls, but contains 15 `<invalid>` stack expressions and goto-heavy control flow |
| `DrawTime` | Passed; widened clock arithmetic and sound branch preserved | Finds timing/sound branches, but retains unresolved stack argument transport |
| `InitBars` | Passed; 43-word temporary array and two-byte bar structure recovered | One of Reko's best bodies: both loops and randomization are recognizable, but types remain Eq-based and pointer-heavy |
| `ReInitBars` | Passed; 32-bit clock store, bar copy, and draw loop are clear | Recovers the 32-bit clock split and copy/draw loop, but array identity is rendered as segment pointer arithmetic |
| `DrawBar` | Passed; 44-byte buffer, fills, terminator, color, and output call are clear | Overall operation is recognizable, but frame-pointer type is `<unknown>` and arguments remain indirect |
| `SwapBars` | Passed; two draw calls and timing call are direct | Finds all three calls, but one recovered stack result is `<invalid>` |
| `Swaps` | Passed; typed two-byte bar pointers and swap are clear | Concise and recognizable swap, but uses generated member-pointer types rather than a recovered `BAR` contract |
| `InsertionSort` | Passed; source-like nested-loop behavior and calls | Recognizable nested loops, but stack object fields and two `<invalid>` values make data flow unreliable |
| `BubbleSort` | Passed; source-like loop and calls | Recognizable loop shape, but generated member-pointer expressions and an `<invalid>` stack value reduce confidence |
| `HeapSort` | Passed; both phases and helper arguments are clear | Finds both heap phases, but one stack value is `<invalid>` and arguments are difficult to audit |
| `PercolateUp` | Passed; source-like loop, comparisons, typed bar pointers, and calls | Recovers the loop and comparisons, but call setup includes an `<invalid>` value and generated pointer-member arithmetic |
| `PercolateDown` | Passed; source-like child selection and swaps | Recovers the main shape, but one `<invalid>` value and opaque generated stack fields obscure argument correctness |
| `ExchangeSort` | Passed; source-like nested loops and swap calls | Recognizable algorithm, but two `<invalid>` values and opaque pointer arithmetic remain |
| `ShellSort` | Passed; source-like offset loops and swap calls | Recognizable nesting, but has `<invalid>` state and malformed-looking signed division syntax (`/16`) |
| `QuickSort` | Passed; pivot loops, swaps, and all recursive arguments recovered | Major failure: 15 `<invalid>` values and eight explicit `Failed to bind call argument` messages in recursive calls |
| `Beep` | Validation failed and the transcript falls back, while retaining partial C for diagnosis | Reko's clearest advantage in this historical comparison: emits the minimum-duration guard, timer division, port writes, sleep, and restore branch without `<invalid>` placeholders |
| `Sleep` | Passed; widened goal and clock comparison are clear | Also strong: reconstructs the 32-bit goal and unsigned low/high-word clock comparison without placeholders |

## What Reko adds

Reko has several useful presentation and exploration features that are absent
or less integrated in this `SORTD.dec` artifact:

- automatic whole-program discovery, including runtime/library procedures;
- `Called from` annotations on every generated procedure;
- one generated global type header spanning the whole program;
- generated C, low-level assembly, and disassembly kept together;
- explicit register outputs and segment state in function contracts;
- fast whole-program analysis for this input (8.96 seconds).

These are useful diagnostics, especially the call graph comments and bundled
multi-level output. They do not establish semantic correctness.

## Trust conclusion

For this binary, Reko is useful as a fast discovery and second-opinion tool,
not as the stronger C producer. It emits all 20 corresponding bodies, but 14
of those bodies contain at least one `<invalid>` or `<unknown>` value. Its
`QuickSort` explicitly loses recursive arguments, and its generated translation
unit is not directly recompilable.

The exact historical `SORTD.dec` is better and closer to `SORTDEMO.C` for 19 of
the 20 application functions because those functions passed Inertia's semantic
validation and expose clearer stack variables, arrays, bar structures, and
call arguments. Reko is better only in availability/readability for `Beep` in
this old snapshot—but unlike Inertia, Reko provides no equivalence verdict to
prove that body.

The current project baseline is newer than `SORTD.dec` and reports the former
`Beep` issue fixed. That newer result must be rerun if a current-tool comparison
is required; it should not be retroactively attributed to this historical file.
