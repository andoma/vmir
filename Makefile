
SRCS  = src/main.c \
	src/vmir.c \
	tlsf/tlsf.c \

DEPS = ${SRCS} \
	Makefile \
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
	src/vmir_libc.c

CFLAGS = -std=gnu99 -Wall -Werror -Wmissing-prototypes -O2 \
	-I${CURDIR}

CFLAGS += -DVMIR_USE_TLSF -I${CURDIR}/tlsf

vmir: ${DEPS}
	$(CC)  ${CFLAGS} -g ${SRCS} -lm -o $@

vmir.arm: ${DEPS}
	$(ARM_CC)  ${CFLAGS} -g ${SRCS} -lm -o $@
