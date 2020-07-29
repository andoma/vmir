cmake_minimum_required(VERSION 3.10)
project(test_misc
	DESCRIPTION "test_misc project"
)

enable_testing()

include(../TestFunc.cmake)

BuildVmirTest("src/*.c")
