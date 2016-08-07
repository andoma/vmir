SRCS  = src/main.c \
	src/vmir.c \
	tlsf/tlsf.c \

DEPS = ${SRCS} \
	Makefile \
	src/vmir.h \
	src/vmir_instr_parse.c \
	src/vmir_value.c \
	src/vmir_type.c \
	src/vmir_jit_arm.c \
	src/vmir_vm.c \
	src/vmir_vm.h \
	src/vmir_transform.c \
	src/vmir_bitstream.c \
	src/vmir_bitcode_parser.c \
	src/vmir_support.c \
	src/vmir_function.c \
	src/vmir_libc.c

CFLAGS = -std=gnu99 -Wall -Werror -Wmissing-prototypes \
	-I${CURDIR}

CFLAGS += -DVMIR_USE_TLSF -I${CURDIR}/tlsf

vmir: ${DEPS}
	$(CC) -O2 ${CFLAGS} -g ${SRCS} -lm -o $@

vmir.dbg: ${DEPS}
	$(CC) -Og -DVM_DONT_USE_COMPUTED_GOTO ${CFLAGS} -g ${SRCS} -lm -o $@

vmir.armv7: ${DEPS}
	arm-linux-gnueabihf-gcc -O2 -static -march=armv7-a -mtune=cortex-a8 -mfpu=neon ${CFLAGS} -g ${SRCS} -lm -o $@

vmir.ppc64: ${DEPS}
	powerpc64-linux-gnu-gcc -O2 -static ${CFLAGS} -g ${SRCS} -lm -o $@

all: vmir vmir.armv7 vmir.ppc64
