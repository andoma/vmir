cmake_minimum_required(VERSION 3.10)
project(gcc-torture
	DESCRIPTION "gcc-torture project"
)

enable_testing()

include(../TestFunc.cmake)

BuildVmirTest("src/*.c")

# vector-src - not work
#BuildVmirTest("vector-src/*.c")
