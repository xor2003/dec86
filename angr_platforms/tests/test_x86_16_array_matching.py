"""
Tests for Phase 2.2: Array Expression Matching

Tests induction variable collection, array pattern detection,
and array recovery metadata synthesis.
"""

import pytest

from angr_platforms.X86_16.type_array_matching import (
    ArrayAccessPattern,
    ArrayExpressionMatcher,
    ArrayRecoveryInfo,
    InductionVariable,
    InductionVariableCollector,
    apply_x86_16_array_expression_matching,
)


class TestInductionVariable:
    """Tests for induction variable representation."""

    def test_create_induction_variable(self):
        """Test creating an induction variable."""
        ind_var = InductionVariable(
            var_name="si", stride=2, base_value=0, loop_bound=100, element_width=16
        )

        assert ind_var.var_name == "si"
        assert ind_var.stride == 2
        assert ind_var.element_width == 16

    def test_induction_variable_repr(self):
        """Test induction variable string representation."""
        ind_var = InductionVariable(
            var_name="di", stride=4, base_value=0, loop_bound=None, element_width=32
        )

        repr_str = repr(ind_var)
        assert "di" in repr_str
        assert "stride=4" in repr_str


class TestArrayAccessPattern:
    """Tests for array access pattern detection."""

    def test_create_array_access_pattern(self):
        """Test creating an array access pattern."""
        pattern = ArrayAccessPattern(
            base_expr="buffer",
            index_var="i",
            stride=2,
            offset=0,
            element_type="int",
            element_width=16,
        )

        assert pattern.base_expr == "buffer"
        assert pattern.index_var == "i"
        assert pattern.stride == 2

    def test_array_access_pattern_repr(self):
        """Test array access pattern representation."""
        pattern = ArrayAccessPattern(
            base_expr="data", index_var="j", stride=4, offset=8, element_type="struct", element_width=32
        )

        repr_str = repr(pattern)
        assert "data" in repr_str
        assert "j" in repr_str


class TestArrayRecoveryInfo:
    """Tests for array recovery metadata."""

    def test_create_array_recovery_info(self):
        """Test creating array recovery metadata."""
        info = ArrayRecoveryInfo(
            array_name="numbers",
            base_ptr="base",
            element_type="int",
            element_width=16,
            element_stride=2,
            access_patterns=set(),
            confidence=0.8,
        )

        assert info.array_name == "numbers"
        assert info.element_type == "int"
        assert info.confidence == 0.8

    def test_array_recovery_info_with_patterns(self):
        """Test array recovery info tracking access patterns."""
        info = ArrayRecoveryInfo(
            array_name="arr",
            base_ptr="ptr",
            element_type="char",
            element_width=8,
            element_stride=1,
            access_patterns={"read[0]", "write[4]"},
            confidence=0.6,
        )

        assert len(info.access_patterns) == 2
        assert "read[0]" in info.access_patterns


class TestInductionVariableCollector:
    """Tests for collecting induction variables."""

    def test_collect_simple_induction(self):
        """Test collecting simple induction variables."""
        collector = InductionVariableCollector()
        expressions = ["si += 2", "di += 4", "cx -= 1"]

        vars = collector.collect(expressions)

        assert "si" in vars
        assert vars["si"].stride == 2
        assert "di" in vars
        assert vars["di"].stride == 4

    def test_stride_pattern_extraction(self):
        """Test extracting stride patterns."""
        collector = InductionVariableCollector()

        collector._analyze_update_expr("bx += 8")

        assert "bx" in collector.stride_patterns
        assert collector.stride_patterns["bx"] == 8

    def test_handle_invalid_stride(self):
        """Test gracefully handling invalid stride expressions."""
        collector = InductionVariableCollector()

        collector._analyze_update_expr("ax += invalid")

        # Should not crash, just skip
        assert "ax" not in collector.stride_patterns


class TestArrayExpressionMatcher:
    """Tests for matching array expressions."""

    def test_looks_like_array_access(self):
        """Test heuristic array access detection."""
        matcher = ArrayExpressionMatcher()

        assert matcher._looks_like_array_access("buffer[0]")
        assert matcher._looks_like_array_access("mem[si]")
        assert matcher._looks_like_array_access("base + i * 2")
        assert not matcher._looks_like_array_access("simple_var")

    def test_match_patterns_with_induction(self):
        """Test matching array patterns with induction variables."""
        matcher = ArrayExpressionMatcher()

        ind_var = InductionVariable(
            var_name="i", stride=2, base_value=0, loop_bound=100, element_width=16
        )
        induction_vars = {"i": ind_var}

        expressions = ["buffer[i]", "mem[si + i * 2]", "data[i]"]

        patterns = matcher.match_patterns(expressions, induction_vars)

        # Should detect at least one array pattern
        assert len(patterns) > 0

    def test_extract_array_pattern(self):
        """Test extracting specific array patterns."""
        matcher = ArrayExpressionMatcher()

        ind_var = InductionVariable(
            var_name="j", stride=4, base_value=0, loop_bound=None, element_width=32
        )
        induction_vars = {"j": ind_var}

        pattern = matcher._extract_array_pattern("arr[j * 4]", induction_vars)

        assert pattern is not None
        assert pattern.index_var == "j"
        assert pattern.stride == 4

    def test_synthesize_arrays_from_patterns(self):
        """Test synthesizing array recovery info from patterns."""
        matcher = ArrayExpressionMatcher()

        patterns = [
            ArrayAccessPattern("buffer", "i", 2, 0, "int", 16),
            ArrayAccessPattern("buffer", "i", 2, 2, "int", 16),
            ArrayAccessPattern("data", "j", 4, 0, "struct", 32),
        ]

        arrays = matcher.synthesize_arrays(patterns)

        assert "buffer" in arrays
        assert "data" in arrays
        assert len(arrays["buffer"].access_patterns) == 2
        assert arrays["buffer"].confidence > 0.5


class TestPhase22Integration:
    """Integration tests for array expression matching."""

    def test_end_to_end_array_matching(self):
        """Test complete array matching pipeline."""
        # Collect induction variables
        collector = InductionVariableCollector()
        expressions = ["si += 2", "di += 4"]
        ind_vars = collector.collect(expressions)

        assert len(ind_vars) > 0

        # Match array patterns
        matcher = ArrayExpressionMatcher()
        access_exprs = ["buffer[si]", "data[di]", "arr[si + 4]"]
        patterns = matcher.match_patterns(access_exprs, ind_vars)

        # Synthesize arrays
        arrays = matcher.synthesize_arrays(patterns)

        assert len(arrays) > 0

    def test_array_matching_decompiler_pass(self):
        """Test array matching pass integration with decompiler."""

        class MockCodegen:
            cfunc = object()

        codegen = MockCodegen()
        result = apply_x86_16_array_expression_matching(codegen)

        assert result is False  # No direct modifications
        assert hasattr(codegen, "_inertia_array_matching_applied")
        assert codegen._inertia_array_matching_applied is True

    def test_multi_dimensional_array_detection(self):
        """Test detecting multi-dimensional array patterns."""
        matcher = ArrayExpressionMatcher()

        ind_var1 = InductionVariable("i", stride=10, base_value=0, loop_bound=100, element_width=16)
        ind_var2 = InductionVariable("j", stride=1, base_value=0, loop_bound=10, element_width=16)

        induction_vars = {"i": ind_var1, "j": ind_var2}

        expressions = ["matrix[i + j * 10]", "grid[i * 10 + j]"]
        patterns = matcher.match_patterns(expressions, induction_vars)

        # Should detect multi-dimensional patterns
        assert len(patterns) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
