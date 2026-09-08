"""Layer: Tests.

Responsibility: execute generated ReInitBars loops without requiring for syntax.
"""

import subprocess
from pathlib import Path


def assert_reinitbars_loop_behavior(body: str, tmp_path: Path) -> None:
    """Check clock count, copy-before-draw, iteration order and untouched entries."""
    source = tmp_path / "reinitbars_loop.c"
    executable = tmp_path / "reinitbars_loop"
    source.write_text(
        """#include <assert.h>
typedef struct { unsigned short value; } bar;
static bar abarWork[4], abarPerm[4];
static unsigned short cRow;
static unsigned long clStart;
static unsigned int draws, clocks;
static long clock(void) { ++clocks; return 123; }
static int DrawBar(unsigned short row) {
    assert(row == draws);
    assert(row < cRow);
    assert(abarWork[row].value == abarPerm[row].value);
    ++draws;
    return 0;
}
""" + body + """
int main(void) {
    const unsigned short rows[] = {0, 1, 3};
    for (unsigned int trial = 0; trial < 3; ++trial) {
        cRow = rows[trial];
        draws = clocks = 0;
        clStart = 0;
        for (unsigned int i = 0; i < 4; ++i) {
            abarPerm[i].value = 10 + i;
            abarWork[i].value = 99;
        }
        ReInitBars();
        assert(clStart == 123 && clocks == 1 && draws == cRow);
        for (unsigned int i = 0; i < 4; ++i)
            assert(abarWork[i].value == (i < cRow ? abarPerm[i].value : 99));
    }
    return 0;
}
""", encoding="utf-8",
    )
    compiled = subprocess.run(
        ["gcc", "-std=c99", "-Wall", "-Wextra", "-Werror", str(source), "-o", str(executable)],
        capture_output=True, text=True, timeout=30, check=False,
    )
    assert compiled.returncode == 0, compiled.stderr
    result = subprocess.run(
        [str(executable)], capture_output=True, text=True, timeout=5, check=False,
    )
    assert result.returncode == 0, result.stderr
