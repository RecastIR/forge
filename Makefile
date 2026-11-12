BUILD_DIR ?= build
build_config = $(or $(CONFIG),Debug)
configure_flags = $(if $(LLVM_DIR),"-DLLVM_DIR=$(LLVM_DIR)") \
                  $(if $(BUILD_TESTING),"-DBUILD_TESTING=$(BUILD_TESTING)") \
                  $(if $(CONFIG),"-DCMAKE_BUILD_TYPE=$(CONFIG)") \
                  $(if $(SANITIZE),"-DFORGE_ENABLE_SANITIZERS=$(SANITIZE)")

.PHONY: build configure test fixtures sanitize clean format format-check lint

build: configure
	cmake --build "$(BUILD_DIR)" --config "$(build_config)" --parallel

configure:
	cmake -S . -B "$(BUILD_DIR)" $(CMAKE_ARGS) $(configure_flags)

test: build
	ctest --test-dir "$(BUILD_DIR)" -C "$(build_config)" --output-on-failure --no-tests=error

fixtures: configure
	ctest --test-dir "$(BUILD_DIR)" -C "$(build_config)" --output-on-failure --no-tests=error -R '^fixtures$$'

sanitize:
	$(MAKE) test BUILD_DIR="$(BUILD_DIR)-sanitize" CONFIG=Debug SANITIZE=ON

format format-check lint:
	cmake "-DACTION=$@" "-DBUILD_DIR=$(BUILD_DIR)-lint" "-DLLVM_CONFIG=$(LLVM_CONFIG)" \
	      "-DLLVM_DIR=$(LLVM_DIR)" "-DLINT_DATABASE=$(LINT_DATABASE)" -P cmake/quality.cmake

clean:
	@if test -f "$(BUILD_DIR)/CMakeCache.txt"; then cmake --build "$(BUILD_DIR)" --config "$(build_config)" --target clean; fi
