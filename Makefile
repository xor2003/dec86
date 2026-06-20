PYTHON ?= python
FILES ?=
PY_FILES_ALL := $(shell git ls-files '*.py')
PY_FILES := $(filter %.py,$(FILES))
PYTEST_FILES := $(filter angr_platforms/tests/%.py tests/%.py,$(PY_FILES))

.PHONY: quality decompiler-check linters linters-files check-files check-all pytest pytest-files pytest-all ruff ruff-files ruff-all pyright pyright-files pyright-all vulture radon test-pipeline msc6-examples sortdemo-selftest monkeytype-trace monkeytype-stubs monkeytype-apply types

quality: linters decompiler-check

decompiler-check: pytest test-pipeline

linters:
	$(MAKE) -j4 ruff pyright vulture radon PYTHON="$(PYTHON)"

linters-files:
	$(MAKE) -j2 ruff-files pyright-files PYTHON="$(PYTHON)" FILES="$(FILES)"

check-files: linters-files pytest-files

check-all: ruff-all pyright-all pytest-all

QA_TYPED_FILES := \
	monkeytype_config.py \
	inertia_decompiler/monkeytype_tools.py \
	scripts/collect_monkeytype_pytest.py \
	scripts/apply_monkeytype_annotations.py \
	scripts/export_monkeytype_stubs.py

QA_RUFF_TARGETS := \
	inertia_decompiler/decompilation_quality.py \
	scripts/sortdemo_decompiler_status.py \
	scripts/test_pipeline.py \
	angr_platforms/tests/test_decompilation_quality.py \
	angr_platforms/tests/test_x86_16_package_exports.py \
	angr_platforms/tests/test_x86_16_heapsort_widening_regression.py \
	angr_platforms/tests/test_x86_16_segmented_global_loads.py \
	angr_platforms/tests/test_x86_16_decompilation_cache_surface.py \
	angr_platforms/tests/test_test_pipeline.py \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py \
	angr_platforms/tests/test_x86_16_source_backed_quality.py \
	angr_platforms/tests/test_x86_16_sortdemo_decompiler_status.py

QA_PYTEST_TARGETS := \
	angr_platforms/tests/test_build_msc6_examples.py \
	angr_platforms/tests/test_test_pipeline.py \
	angr_platforms/tests/test_x86_16_package_exports.py \
	angr_platforms/tests/test_x86_16_sortdemo_decompiler_status.py \
	angr_platforms/tests/test_x86_16_heapsort_widening_regression.py \
	angr_platforms/tests/test_x86_16_segmented_global_loads.py \
	angr_platforms/tests/test_x86_16_decompilation_cache_surface.py \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_heapsort_callsites_materialized_in_c_order \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_percolateup_materializes_parent_once_and_preserves_calls \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_percolateup_anchor_no_longer_crashes_on_vexvalue_register_resolution \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_acceptance_scorecards_capture_main_sleep_and_percolateup_state \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_reinitbars_uses_runtime_segment_helpers_and_keeps_validation_clean \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_drawtime_materializes_clock_return_to_clfinish_once \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_reinitbars_stable_stack_slot_irow_materialized \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_initbars_getvideoconfig_far_pointer_call_has_no_stack_setup_remnants \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_initmenu_pause_zero_guard_has_no_raw_flag_carrier \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_insertionsort_word_stores_materialized_without_raw_high_byte_memory \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_drawbar_word_stride_byte_fields_validate_without_indexed_mem_helper_syntax \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_percolatedown_direct_global_increment_materialized \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_reinitbars_recurrence_rebound_to_irow \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_swapbars_call_arguments_materialized \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_swapbars_does_not_pointer_promote_irow2_or_emit_dead_setup_artifacts \
	angr_platforms/tests/test_x86_16_sortdemo_regressions.py::test_sortdemo_swaps_preserves_binary_proven_global_increment_and_pointer_swap \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_callsites.py::test_normalize_call_target_names_drops_detached_angr_callee_func \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_callsites.py::test_callsite_stats_count_stale_target_rejection \
	angr_platforms/tests/test_x86_16_access_trait_arrays.py \
	angr_platforms/tests/test_x86_16_access_trait_policy.py \
	angr_platforms/tests/test_x86_16_access_trait_strides.py \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_utils.py \
	angr_platforms/tests/test_x86_16_segmented_memory.py \
	angr_platforms/tests/test_x86_16_type_equivalence_classes.py

PYRIGHT_SELECTED_FILES := $(filter $(QA_TYPED_FILES),$(PY_FILES))
PYRIGHT_SKIPPED_FILES := $(filter-out $(QA_TYPED_FILES),$(PY_FILES))

pytest:
	INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE=$${INERTIA_TEST_DECOMPILE_TIMEOUT_SCALE:-4} $(PYTHON) -m pytest -q $(QA_PYTEST_TARGETS)

pytest-files:
	@if [ -n "$(strip $(PYTEST_FILES))" ]; then \
		$(PYTHON) -m pytest -q $(PYTEST_FILES); \
	else \
		echo "pytest-files: no test files selected"; \
	fi

pytest-all:
	$(PYTHON) -m pytest -q

ruff:
	$(PYTHON) -m ruff check --fix $(QA_RUFF_TARGETS)

ruff-files:
	@test -n "$(strip $(PY_FILES))" || (echo 'ruff-files: no Python files selected'; exit 0)
	$(PYTHON) -m ruff check --fix $(PY_FILES)

ruff-all:
	$(PYTHON) -m ruff check --fix $(PY_FILES_ALL)

pyright:
	$(PYTHON) -m pyright $(QA_TYPED_FILES)

pyright-files:
	@test -n "$(strip $(PY_FILES))" || (echo 'pyright-files: no Python files selected'; exit 0)
	@if [ -n "$(strip $(PYRIGHT_SELECTED_FILES))" ]; then \
		$(PYTHON) -m pyright $(PYRIGHT_SELECTED_FILES); \
	else \
		echo "pyright-files: no promoted typed files selected"; \
	fi
	@if [ -n "$(strip $(PYRIGHT_SKIPPED_FILES))" ]; then \
		echo "pyright-files: skipped legacy files not in QA_TYPED_FILES: $(PYRIGHT_SKIPPED_FILES)"; \
	fi

pyright-all:
	$(PYTHON) -m pyright

vulture:
	$(PYTHON) -m vulture $(QA_TYPED_FILES)

radon:
	$(PYTHON) -m radon cc scripts inertia_decompiler --show-complexity --min C

test-pipeline:
	$(PYTHON) scripts/test_pipeline.py --require-external

msc6-examples:
	INERTIA_ENABLE_TAIL_VALIDATION=1 INERTIA_DISABLE_TIMING=1 $(PYTHON) scripts/build_msc6_examples.py --skip-constructs medium_structs,enum_union --decompile-mode functions --decompile-max-functions 0 --decompile-timeout 60 --decompile-run-timeout 600

sortdemo-selftest:
	$(PYTHON) scripts/build_sortdemo_selftest.py --clean

monkeytype-trace:
	$(PYTHON) scripts/collect_monkeytype_pytest.py

monkeytype-stubs:
	$(PYTHON) scripts/export_monkeytype_stubs.py

monkeytype-apply:
	$(PYTHON) scripts/apply_monkeytype_annotations.py

types: monkeytype-trace monkeytype-apply
