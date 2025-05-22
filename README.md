Decompiler for X86 16 bit

TODO: Unreal mode

## Setup and Dependencies

Some basic dependencies can be installed using:
`pip install -r requirements.txt`

However, this project has specific and currently problematic an angr dependency:

**Core Dependencies:**

1.  **`https://github.com/xor2003/angr-platforms`**:
    *   This component is required.
    *   It can be installed via the `requirements.txt` file (`git+https://github.com/xor2003/angr-platforms.git#egg=angr-platforms`).

2.  **`https://github.com/xor2003/angr`**:
    *   This specific angr fork (`xor2003/angr`) is listed as a primary requirement for the decompiler's logic.
    *   **WARNING: This fork is NOT currently installable through standard `pip` mechanisms.**
    *   It depends on exact `.dev0` versions of several angr components (e.g., `pyvex==9.2.107.dev0`, `ailment==9.2.107.dev0`, `archinfo==9.2.107.dev0`, `claripy==9.2.107.dev0`, `cle==9.2.107.dev0`).
    *   These specific `.dev0` versions are not available on the Python Package Index (PyPI).
    *   The `xor2003` GitHub repositories for these individual dependencies (e.g., `xor2003/pyvex`, `xor2003/ailment`) could not be found or accessed.
    *   **Users will need to manually source, build, or otherwise obtain these exact `.dev0` dependency versions to make the `xor2003/angr` fork usable.** Without this, the decompiler will not run.
    *   Users might need to explore alternative, publicly available `angr` versions or forks if they cannot resolve the `xor2003/angr` dependency issues.

## Usage

**WARNING: The following command will FAIL unless the `xor2003/angr` dependency and its specific `.dev0` components (as detailed in "Setup and Dependencies") have been manually resolved and correctly installed.**

`./decompile.py test.bin`
