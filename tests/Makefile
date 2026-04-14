ROOT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
UNIT_DIR := $(ROOT_DIR)/tests/unit
UNIT_BUILD_DIR := $(UNIT_DIR)/build
FUZZING_DIR := $(ROOT_DIR)/tests/fuzzing
FUZZING_BUILD_DIR := $(FUZZING_DIR)/build
MAKEFLAGS += --no-print-directory
TARGET ?= stax
JOBS ?= 8
PYLINT_JOBS ?= $(JOBS)
CTEST_JOBS ?= $(JOBS)
FUZZ_SECONDS ?= 1

ifneq ($(wildcard $(ROOT_DIR)/tests/venv/bin/python),)
PYTHON ?= $(ROOT_DIR)/tests/venv/bin/python
else
PYTHON ?= python3
endif

.PHONY: help python-checks clang-format-src-check clang-format-generated-check tests-unit generated-fixture-drift unit-build unit-run unit-coverage fuzzing

help:
	@echo "Available targets:"
	@echo "  make -C tests python-checks Run Ruff format check, pylint, and mypy"
	@echo "  make -C tests clang-format-src-check Check clang-format-14 on src/*.c and src/*.h"
	@echo "  make -C tests tests-unit    Regenerate unit fixtures, check drift, build, and run unit tests"
	@echo "  make -C tests unit-coverage  Build, run unit tests, and generate HTML coverage report"
	@echo "  make -C tests fuzzing       Build fuzzing harnesses and run each for $(FUZZ_SECONDS) seconds"

python-checks:
	cd $(ROOT_DIR) && ruff format . --exclude tests/venv --check
	cd $(ROOT_DIR) && pylint -j $(PYLINT_JOBS) --rcfile=.pylintrc tests/application_client tests/standalone tests/swap
	cd $(ROOT_DIR) && mypy --config-file mypy.ini

clang-format-src-check:
	@cd $(ROOT_DIR) && \
	if command -v clang-format-14 >/dev/null 2>&1; then \
		SRC_FILE_SAMPLE="$$(find src -type f \( -name '*.c' -o -name '*.h' \) -print -quit)"; \
		if [ -n "$$SRC_FILE_SAMPLE" ]; then \
			find src -type f \( -name '*.c' -o -name '*.h' \) -print0 | sort -z | xargs -0 -n 32 -P $(JOBS) clang-format-14 --dry-run --Werror; \
		fi; \
	else \
		echo "WARNING: clang-format-14 not found; skipping src C formatting check"; \
	fi

clang-format-generated-check:
	@cd $(ROOT_DIR) && \
	if command -v clang-format-14 >/dev/null 2>&1; then \
		GENERATED_FILE_SAMPLE="$$(find tests/unit/generated tests/unit/mock_crypto -type f \( -name '*.c' -o -name '*.h' \) -print -quit)"; \
		if [ -n "$$GENERATED_FILE_SAMPLE" ]; then \
			find tests/unit/generated tests/unit/mock_crypto -type f \( -name '*.c' -o -name '*.h' \) -print0 | sort -z | xargs -0 -n 32 -P $(JOBS) clang-format-14 --dry-run --Werror; \
		fi; \
	else \
		echo "WARNING: clang-format-14 not found; skipping generated C formatting check"; \
	fi

tests-unit: generated-fixture-drift unit-build unit-run

generated-fixture-drift:
	cd $(ROOT_DIR) && PYTHONPATH=. $(PYTHON) -m tests.unit.generators.generate_unit_tests_from_ragger all
	$(MAKE) clang-format-generated-check
	cd $(ROOT_DIR) && git diff --exit-code -- tests/unit/generated tests/unit/mock_crypto/crypto_mock_data.h

unit-build:
	cmake -S $(UNIT_DIR) -B $(UNIT_BUILD_DIR)
	cmake --build $(UNIT_BUILD_DIR) -j$(JOBS)

unit-run:
	CTEST_OUTPUT_ON_FAILURE=1 ctest --test-dir $(UNIT_BUILD_DIR) --output-on-failure --parallel $(CTEST_JOBS)

unit-coverage:
	cmake -S $(UNIT_DIR) -B $(UNIT_BUILD_DIR) --fresh
	cmake --build $(UNIT_BUILD_DIR) -j$(JOBS)
	CTEST_OUTPUT_ON_FAILURE=1 ctest --test-dir $(UNIT_BUILD_DIR) --output-on-failure --parallel $(CTEST_JOBS)
	cd $(UNIT_DIR) && bash gen_coverage.sh

fuzzing:
	@test -n "$(BOLOS_SDK)" || (echo "BOLOS_SDK must be set for fuzzing builds" && exit 1)
	GNUMAKEFLAGS=--no-print-directory cmake -S $(FUZZING_DIR) -B $(FUZZING_BUILD_DIR) -DBOLOS_SDK=$(BOLOS_SDK) -DTARGET=$(TARGET) -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug -DSANITIZER=address
	GNUMAKEFLAGS=--no-print-directory cmake --build $(FUZZING_BUILD_DIR) -j$(JOBS)
	cd $(FUZZING_DIR) && ./run_all_fuzzers.sh $(FUZZ_SECONDS)
