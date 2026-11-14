.DEFAULT_GOAL := build

export BUILD_ROOT BUILD_DIR PRESET CONFIG BUILD_TESTING SANITIZE CMAKE_ARGS CTEST_ARGS
export LLVM_DIR LLVM_CONFIG LINT_DATABASE CONAN_HOST_PROFILE CONAN_BUILD_PROFILE WITH_CLI CACHE_ONLY

.PHONY: build configure test fixtures sanitize lint clean provision provision-fixtures update-lock format format-check format-audit

build configure test fixtures sanitize lint clean provision update-lock:
	@python3 -B cmake/workflow.py $@

provision-fixtures:
	@python3 -B tests/differential/fixture_images.py --provision

format format-check format-audit:
	@cmake -DACTION=$@ -P cmake/quality.cmake
