CLANG=${LLVM_TOOLCHAIN}clang${LLVM_VERSION}
LLC=${LLVM_TOOLCHAIN}llc${LLVM_VERSION}
SRCFILES = $(shell find src/ -type f -name '*.c')
CFILES = $(patsubst src/%.c, %, $(SRCFILES))


O0FILES = ${patsubst %, build-O0/%.bc, ${CFILES}}
O1FILES = ${patsubst %, build-O1/%.bc, ${CFILES}}
O2FILES = ${patsubst %, build-O2/%.bc, ${CFILES}}
WASMFILES = ${patsubst %, wasm-Oz/%.wasm, ${CFILES}}

SYSROOT = $(shell cd ../../sysroot/ && pwd)

CFLAGS_WASM=-emit-llvm --target=wasm32 -Oz
CFLAGS_BC=-fno-vectorize -fno-slp-vectorize -emit-llvm -target le32-unknown-nacl
CFLAGS += --sysroot=${SYSROOT} -I${SYSROOT}/usr/include -std=gnu99

.PHONY: all wasm
bc: ${O0FILES} ${O1FILES} ${O2FILES}
wasm: ${WASMFILES}

build-O0/%.bc: src/%.c Makefile
	@mkdir -p "$(@D)"
	${CLANG} -O0 ${CFLAGS_BC} ${CFLAGS} -c $< -o $@

build-O1/%.bc: src/%.c Makefile
	@mkdir -p "$(@D)"
	${CLANG} -O1 ${CFLAGS_BC} ${CFLAGS} -c $< -o $@

build-O2/%.bc: src/%.c Makefile
	@mkdir -p "$(@D)"
	${CLANG} -O2 ${CFLAGS_BC} ${CFLAGS} -c $< -o $@


.PRECIOUS: wasm-Oz/%.bc wasm-Oz/%.s wasm-Oz/%.wast

wasm-Oz/%.bc: src/%.c Makefile
	@mkdir -p "$(@D)"
	${CLANG} -Oz ${CFLAGS_WASM} ${CFLAGS} -c $< -o $@

wasm-Oz/%.s: wasm-Oz/%.bc Makefile
	${LLC} -asm-verbose=false -o $@ $<

wasm-Oz/%.wast: wasm-Oz/%.s Makefile
	s2wasm $< >$@

wasm-Oz/%.wasm: wasm-Oz/%.wast Makefile
	wast2wasm $< -o $@
