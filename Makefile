BUILD_DIR ?= build
BUILD_TESTING ?= ON

# Honor an explicit LLVM_DIR, then try the verified Homebrew toolchain.
ifndef LLVM_DIR
LLVM_DIR := $(shell prefix=$$(brew --prefix llvm@17 2>/dev/null) && "$$prefix/bin/llvm-config" --cmakedir 2>/dev/null)
endif

.PHONY: build configure test fixtures sanitize clean

build: configure
	cmake --build "$(BUILD_DIR)" --parallel

configure:
	cmake -S . -B "$(BUILD_DIR)" $(if $(LLVM_DIR),"-DLLVM_DIR=$(LLVM_DIR)") -DBUILD_TESTING=$(BUILD_TESTING) $(CMAKE_ARGS)

test: build
	ctest --test-dir "$(BUILD_DIR)" --output-on-failure --no-tests=error

fixtures: configure
	ctest --test-dir "$(BUILD_DIR)" --output-on-failure --no-tests=error -R '^fixtures$$'

sanitize:
	$(MAKE) test BUILD_DIR="$(BUILD_DIR)-sanitize" \
		CMAKE_ARGS='-DCMAKE_BUILD_TYPE=Debug "-DCMAKE_CXX_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer"'

clean:
	@if test -f "$(BUILD_DIR)/CMakeCache.txt"; then cmake --build "$(BUILD_DIR)" --target clean; fi
