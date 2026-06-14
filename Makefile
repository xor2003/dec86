PYTHON ?= python
FILES ?=
PY_FILES_ALL := $(shell git ls-files '*.py')
PYTEST_FILES := $(filter angr_platforms/tests/%.py tests/%.py,$(FILES))

.PHONY: quality decompiler-check check-files check-all pytest pytest-files pytest-all ruff ruff-files ruff-all pyright pyright-files pyright-all vulture radon test-pipeline msc6-examples sortdemo-selftest monkeytype-trace monkeytype-stubs monkeytype-apply types

quality: ruff pyright vulture radon decompiler-check

decompiler-check: pytest test-pipeline

check-files: ruff-files pyright-files pytest-files

check-all: ruff-all pyright-all pytest-all

QA_TYPED_FILES := \
	monkeytype_config.py \
	inertia_decompiler/monkeytype_tools.py \
	scripts/collect_monkeytype_pytest.py \
	scripts/apply_monkeytype_annotations.py \
	scripts/export_monkeytype_stubs.py

QA_RUFF_TARGETS := \
	$(QA_TYPED_FILES) \
	inertia_decompiler/decompilation_quality.py \
	scripts/sortdemo_decompiler_status.py \
	scripts/test_pipeline.py \
	angr_platforms/tests/test_decompilation_quality.py \
	angr_platforms/tests/test_test_pipeline.py \
	angr_platforms/tests/test_x86_16_source_backed_quality.py \
	angr_platforms/tests/test_x86_16_sortdemo_decompiler_status.py

QA_PYTEST_TARGETS := \
	angr_platforms/tests/test_build_msc6_examples.py \
	angr_platforms/tests/test_test_pipeline.py \
	angr_platforms/tests/test_x86_16_access_trait_arrays.py \
	angr_platforms/tests/test_x86_16_access_trait_policy.py \
	angr_platforms/tests/test_x86_16_access_trait_strides.py \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_utils.py \
	angr_platforms/tests/test_x86_16_segmented_memory.py \
	angr_platforms/tests/test_x86_16_type_equivalence_classes.py

pytest:
	$(PYTHON) -m pytest -q $(QA_PYTEST_TARGETS)

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
	@test -n "$(strip $(FILES))" || (echo 'usage: make ruff-files FILES="path/to/file.py [...]"' >&2; exit 2)
	$(PYTHON) -m ruff check --fix $(FILES)

ruff-all:
	$(PYTHON) -m ruff check --fix $(PY_FILES_ALL)

pyright:
	$(PYTHON) -m pyright $(QA_TYPED_FILES)

pyright-files:
	@test -n "$(strip $(FILES))" || (echo 'usage: make pyright-files FILES="path/to/file.py [...]"' >&2; exit 2)
	$(PYTHON) -m pyright $(FILES)

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
