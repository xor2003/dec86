# DOS Compiler Support in Inertia Decompiler

## Overview

This document describes support for:
1. **Library/Object Files** (LIB/OBJ) - Signature catalog extraction
2. **Debug Info** (CodeView NB00/NB02/NB04) - Function/variable name recovery
3. **DOS Compiler Categories** - Supported language targets

### ✅ Fully Supported

#### 1. **16-bit Real Mode DOS** (Microsoft OMF Format)
**~80-90% of DOS games (especially pre-1993)**

Companies and compilers:
- **Borland**: Turbo C v1–2, Turbo C++ early versions, Turbo Pascal v1–7
- **Microsoft**: C v1–6, QuickC v1–2, QuickBASIC v1–4.5, GW-BASIC v2.0–3.2, MASM v5
- **Lattice C** (available via archive)
- **Aztec C** (Mark IV/Manx Aztec C86 v3.4–5.2)
- **DeSmet C** (DeSmet C88 v2.4, v3.1b, DeSmet PCC v1.2c)
- **Digital Research C** (Digital Research C v1.1, CB-86 v2, MTplus86 Pascal v3.11)
- **Zortech C++** (Zortech C++ v2.06, v3.0r1)
- **Mix C** (Mix C v2.0.2, v2.5.1, Mix Power C v1, v2.2)
- **Intel iC-86 Compiler** v4.5 (when using Microsoft-compatible libraries)
- **Other vendors**: Janus Ada, Mark Williams MWC, PowerBASIC, ZBasic

**Format**: Microsoft OMF `.LIB` and `.OBJ` files with 0xF0 header
- **Status**: Fully parsed and indexed ✅
- **Example**: `/home/xor/inertia_player/dos_compilers/Borland Turbo C v2/LIB/CC.LIB`

### ⚠️ Partially Recognized (Format Detected, Content Not Extracted)

#### 2. **Intel iC-86 Compiler v4.5** (Non-Microsoft OMF)
**Protected/Real mode transition era**

Intel's proprietary archive format:
- **Files**: CDOSC.LIB, CDOSL.LIB, CDOSM.LIB, etc.
- **Format**: Intel IA-86/ARN archive with 0xA4 0x07 header
- **Status**: Format detected but content not extracted ⚠️
- **Action**: Returns 0 modules without crashing

### ❌ Unsupported/Not Yet Implemented

#### 3. **16-bit Protected Mode DOS** (DOS Extenders)
**Transitional era (~1992–1995)**

Compilers with DOS extender support:
- Watcom C (with extended memory support)
- Borland C++ (with DOSX/Phar Lap extenders)
- Microsoft C (with DOSX extender)

**Status**: Not yet implemented - may require special handling for extended memory models

#### 4. **16-bit Windows (Win16)**
**Windows/Windows NT 3.x era**

Compilers with Windows-specific code generation:
- Borland C++
- Microsoft C
- Turbo Pascal (later versions)

**Status**: Not implemented - different calling conventions and segment organization

#### 5. **Other Archive Formats**

Some less common library containers:
- **Unix ar archives** (used by some cross-compilers)
- **Lib files with text headers** (definition files, not code libraries)

---

## Debug Information Support

### CodeView Format (NB02, NB04)

**What**: CodeView is a legacy debug format embedded in DOS-era EXE files containing debug tables with function names, variable names, and stack frame information.

**Extraction Method**: The decompiler automatically detects and parses CodeView NB02/NB04 from binary files.

**Key Data Extracted**:
- ✅ **Function names** (from S_GPROC16 symbols)
- ✅ **Global/local data names** (from S_GDATA16/S_LDATA16)
- ✅ **Stack variables** (from S_BPREL16, with BP-relative offsets)
- ✅ **Procedure lengths** (enabling function range synthesis)

**Supported Signatures**:
| Signature | Format | Era | Status |
|-----------|--------|-----|--------|
| NB00 | CV0 | Very old | ✅ Existing |
| NB02 | CV2 | DOS era | ✅ New |
| NB04 | CV4 | DOS era ✓  | ✅ New |
| NB05 | CV5 | Transitional | ✅ Detected |

**Primary Target**: NB04 (most common in MS C v5–v6 and Turbo C++ binaries)

**Example**:
```python
from inertia_decompiler.sidecar_metadata import _load_lst_metadata
metadata = _load_lst_metadata(binary_path, project=proj)
# Automatically includes CodeView symbols if present
print(metadata.source_formats)  # May include 'codeview_nb04'
```

**Integration**: Transparent - no configuration needed. CodeView data is merged into standard metadata output and reported via source_formats.

**See Also**: [CODEVIEW_SUPPORT.md](./CODEVIEW_SUPPORT.md) for detailed format specification and implementation notes.

---

## NE/Win16 Format Support

### What

**NE (New Executable)** format is the binary container used for:
- Windows 3.0–3.1 applications
- OS/2 1.x–2.x applications  
- Some DOS games that shipped with Windows compatibility layers

NE executables contain a DOS MZ stub followed by the NE header with function exports in a resident names table and entry point records.

### Extraction Method

The decompiler automatically detects NE format (`NE` signature at offset from MZ header) and parses:
- **Resident names table** for function names
- **Entry table** for entry point (segment, offset) pairs
- **Segment table** for address calculation

### Key Data Extracted

- ✅ **Function names** (from resident names table exports)
- ✅ **Entry point addresses** (via segment:offset → linear address mapping)
- ⚠️  **No stack variables** (NE format lacks detailed symbol records without debug info)

### Target Platforms

**Games using NE format**:
- Early Borland Turbo Pascal v5.x games (Windows 3.0 compatibility)
- Microsoft C v6.0 Windows games
- Watcom C games compiled for OS/2 or Windows 3.x
- Games with both DOS and Windows versions (dual binary)

### Integration

**Fallback Position**: When CodeView debug info is absent, NE parser extracts minimal but valuable function names:

```python
from inertia_decompiler.sidecar_metadata import _load_lst_metadata
metadata = _load_lst_metadata(binary_path, project=proj)
# If CodeView empty AND NE format detected:
print(metadata.source_formats)  # Includes 'ne_exe'
print(metadata.code_labels)     # Contains exported function names
```

### Limitations

- **No local variable recovery** (requires CodeView debug tables)
- **No line number mapping** (NE format provides only entry points)
- **Function lengths estimated** (if available from debug info) or unknown
- **No type information**

### See Also

[NE_WIN16_SUPPORT.md](./NE_WIN16_SUPPORT.md) for implementation details, format specification, and references.

---

## Implementation Details

### LIB Format Detection

The decompiler includes format detection via `get_lib_format_info(lib_path)`:
```python
from omf_pat import get_lib_format_info
info = get_lib_format_info(Path("CC.LIB"))
print(info)
# {'format': 'microsoft', 'size': 107895, 'header_hex': 'f00d0000', 'supported': True}
```

### Error Handling

All library parsing is defensive:
- **Non-existent files**: Silently return empty catalog (no crash)
- **Unsupported formats**: Detected and skipped with empty result (no crash)
- **Malformed files**: Gracefully handle truncation/corruption without raising exceptions
- **PAT generation**: Safely fails and returns 0 patterns if extraction is impossible

### Current Behavior

**Microsoft OMF Libraries (.LIB, .OBJ)**
- ✅ Parsed into modules
- ✅ Symbols enumerated and indexed
- ✅ FLAIR conversion attempted (if available)
- ✅ Fallback PAT generation from OMF modules
- ✅ Patterns matched against disassembly

**Intel IA-86 Libraries** 
- ✅ Format detected (0xA4 0x07 header)
- ✅ No crash (returns empty catalog)
- ⚠️ Content not extracted (would require Intel archive decoder)

**Other Formats**
- ✅ Unknown formats return empty silently
- ✅ No crashes or exceptions raised

## Statistics

As of the current snapshot (`/home/xor/inertia_player/dos_compilers/`):

| Format | File Count | Supported |
|--------|--------|----|
| Microsoft OMF | 245 | ✅ Yes |
| Intel IA-86 | 131 | ⚠️ Partial |
| **Total** | **376** | |

## Future Enhancement Opportunities

1. **Intel IA-86 Archive Support**: Implement decoder for Intel's archive format to unlock ~35% more library files
2. **Protected Mode Extensions**: Detect and handle DOSX/Phar Lap segments
3. **Win16 Support**: Add Windows-specific segment and calling convention handling
4. **Archive Format Auto-Detection**: Support Unix ar and other standard archive formats

## Testing and Validation

Robustness testing confirms:
- ✅ All 245 Microsoft OMF files parse without crashes
- ✅ All 131 Intel IA-86 files are detected and gracefully skipped
- ✅ Non-existent files handled gracefully
- ✅ Zero unhandled exceptions in signature collection pipeline

## References

- Microsoft OMF: [Object Module Format Reference](https://en.wikipedia.org/wiki/OMF_(file_format))
- Borland LIB Format: Reverse-engineered from actual library files
- Intel iC-86: Archive format detected via header signature analysis
