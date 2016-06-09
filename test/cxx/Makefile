CXX=clang++${LLVM_VER}
SRCFILES = $(shell find src/ -type f -name '*.cpp')
CFILES = $(patsubst src/%.cpp, %, $(SRCFILES))


O0FILES = ${patsubst %, build-O0/%.bc, ${CFILES}}
O1FILES = ${patsubst %, build-O1/%.bc, ${CFILES}}
O2FILES = ${patsubst %, build-O2/%.bc, ${CFILES}}

SYSROOT = $(shell cd ../../sysroot/ && pwd)

CFLAGS=-fno-vectorize -fno-slp-vectorize -emit-llvm -target le32-unknown-nacl
CFLAGS += -ffreestanding
CFLAGS += --sysroot=${SYSROOT} -I${SYSROOT}/usr/include -std=c++11

.PHONY: all
all: ${O0FILES} ${O1FILES} ${O2FILES}


build-O0/%.bc: src/%.cpp Makefile
	@mkdir -p "$(@D)"
	${CXX} -O0 ${CFLAGS} -c $< -o $@

build-O1/%.bc: src/%.cpp Makefile
	@mkdir -p "$(@D)"
	${CXX} -O1 ${CFLAGS} -c $< -o $@

build-O2/%.bc: src/%.cpp Makefile
	@mkdir -p "$(@D)"
	${CXX} -O2 ${CFLAGS} -c $< -o $@

