PYTHON ?= python

.PHONY: quality pytest ruff pyright vulture radon msc6-examples monkeytype-trace monkeytype-stubs monkeytype-apply types

quality: ruff pyright vulture radon pytest

QA_TYPED_FILES := \
	monkeytype_config.py \
	inertia_decompiler/monkeytype_tools.py \
	scripts/collect_monkeytype_pytest.py \
	scripts/apply_monkeytype_annotations.py \
	scripts/export_monkeytype_stubs.py

QA_PYTEST_TARGETS := \
	angr_platforms/tests/test_build_msc6_examples.py \
	angr_platforms/tests/test_x86_16_access_trait_arrays.py \
	angr_platforms/tests/test_x86_16_access_trait_policy.py \
	angr_platforms/tests/test_x86_16_access_trait_strides.py \
	angr_platforms/tests/test_x86_16_decompiler_postprocess_utils.py \
	angr_platforms/tests/test_x86_16_segmented_memory.py \
	angr_platforms/tests/test_x86_16_type_equivalence_classes.py

pytest:
	$(PYTHON) -m pytest -q $(QA_PYTEST_TARGETS)

ruff:
	$(PYTHON) -m ruff check $(QA_TYPED_FILES)

pyright:
	$(PYTHON) -m pyright $(QA_TYPED_FILES)

vulture:
	$(PYTHON) -m vulture $(QA_TYPED_FILES)

radon:
	$(PYTHON) -m radon cc scripts inertia_decompiler --show-complexity --min C

msc6-examples:
	INERTIA_ENABLE_TAIL_VALIDATION=1 INERTIA_DISABLE_TIMING=1 $(PYTHON) scripts/build_msc6_examples.py --skip-constructs medium_structs,enum_union --decompile-mode functions --decompile-max-functions 0 --decompile-timeout 60 --decompile-run-timeout 600

monkeytype-trace:
	$(PYTHON) scripts/collect_monkeytype_pytest.py

monkeytype-stubs:
	$(PYTHON) scripts/export_monkeytype_stubs.py

monkeytype-apply:
	$(PYTHON) scripts/apply_monkeytype_annotations.py

types: monkeytype-trace monkeytype-apply
