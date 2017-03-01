# Helper to build wasm output from C source
# See each example directory for top level Makefile
#
# This assumes $WASM_TOOLCHAIN environment points to tool-chain prefix for LLVM
#
# And binaryen and wabt are in $PATH
#

CLANG=${WASM_TOOLCHAIN}clang
LLC=${WASM_TOOLCHAIN}llc
LINK=${WASM_TOOLCHAIN}llvm-link
BCFILES   = ${patsubst %.c, build/%.bc,   ${SRCS}}
CFLAGS_WASM=-emit-llvm --target=wasm32 -Oz
SYSROOT = $(shell cd ../../../sysroot/ && pwd)
CFLAGS += --sysroot=${SYSROOT} -I${SYSROOT}/usr/include -std=gnu99

.DEFAULT_GOAL := build/${PROGNAME}.wasm

.PRECIOUS: build/%.bc build/%.s build/%.wast

build/%.wasm: build/%.wast Makefile
	@mkdir -p "$(@D)"
	wast2wasm $< -o $@

build/%.wast: build/%.s Makefile
	@mkdir -p "$(@D)"
	s2wasm $< >$@

build/%.s: build/%.link Makefile
	@mkdir -p "$(@D)"
	${LLC} -asm-verbose=false -o $@ $<

build/${PROGNAME}.link: ${BCFILES} Makefile
	@mkdir -p "$(@D)"
	${LINK} -o $@ ${BCFILES}

build/%.bc: %.c Makefile
	@mkdir -p "$(@D)"
	${CLANG} -Oz ${CFLAGS_WASM} ${CFLAGS} -c $< -o $@

clean:
	rm -rf build
