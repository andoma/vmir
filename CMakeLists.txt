cmake_minimum_required(VERSION 3.10)
project(vmir
	DESCRIPTION "vmir project"
)

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/tlsf)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)

set(SRCS 
	src/main.c
	src/vmir.c
	tlsf/tlsf.c
	)

set(DEPS 
	src/vmir.h
	src/vmir_instr.c
	src/vmir_value.c
	src/vmir_type.c
	src/vmir_jit_arm.c
	src/vmir_vm.c
	src/vmir_vm.h
	src/vmir_transform.c
	src/vmir_bitstream.c
	src/vmir_support.c
	src/vmir_function.c
	src/vmir_libc.c
	src/vmir_bitcode_parser.c
	src/vmir_bitcode_instr.c
	src/vmir_wasm_parser.c
	)

set(COMMON_FLAG
	-std=gnu99
	-Wall
	-Werror
	-Wmissing-prototypes
	-DVMIR_USE_TLSF
	)

function(add_vmir_executable a_ExeFileName a_Flags)
	add_executable(${a_ExeFileName} 
		${SRCS}
		)
	target_compile_options(${a_ExeFileName} PRIVATE ${a_Flags})
	target_link_libraries(${a_ExeFileName} m)
	set_target_properties(${a_ExeFileName} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/")
endfunction()

set(VMIR_FLAG -O2 ${COMMON_FLAG} -g)
add_vmir_executable(vmir ${VMIR_FLAG})

set(VMIR_DBG_FLAG -Og -DVM_DONT_USE_COMPUTED_GOTO ${COMMON_FLAG} -g)
add_vmir_executable(vmir.dbg  ${VMIR_DBG_FLAG})

set(VMIR_TRACE_FLAG -DVM_TRACE -Og -DVM_DONT_USE_COMPUTED_GOTO ${COMMON_FLAG} -g)
add_vmir_executable(vmir.trace  ${VMIR_TRACE_FLAG})

set(VMIR_ASAN_FLAG -fno-omit-frame-pointer -fsanitize=address -O0 -DVM_DONT_USE_COMPUTED_GOTO ${COMMON_FLAG} -g)
add_vmir_executable(vmir.asan  ${VMIR_ASAN_FLAG})
target_link_libraries(vmir.asan asan)

set(ARM_GCC arm-linux-gnueabihf-gcc)
find_package(${ARM_GCC})
if (${ARM_GCC}_FOUND)
	set(CMAKE_C_COMPILER ${ARM_GCC})

	set(VMIR_ARMV7_FLAG -O2 -static -march=armv7-a -mtune=cortex-a8 -mfpu=neon ${COMMON_FLAG} -g)
	add_vmir_executable(vmir.armv7  ${VMIR_ARMV7_FLAG})
endif()

set(POWERPC64_GCC arm-linux-gnueabihf-gcc)
find_package(${POWERPC64_GCC})
if (${POWERPC64_GCC}_FOUND)
	set(CMAKE_C_COMPILER ${POWERPC64_GCC})

	set(VMIR_PPC64_FLAG -fno-omit-frame-pointer -fsanitize=address -O0 -DVM_DONT_USE_COMPUTED_GOTO -DVMIR_USE_TLSF ${COMMON_FLAG} -g)
	add_vmir_executable(vmir.ppc64  ${VMIR_PPC64_FLAG})
endif()

enable_testing()
add_subdirectory(test)


