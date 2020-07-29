cmake_minimum_required(VERSION 3.10)
project(regress_test
	DESCRIPTION "regress_test project"
)

enable_testing()

include(../TestFunc.cmake)

BuildRegressTest("stackl_test/*.c")

BuildRegressTest("c-testsuite/single-exec/*.c")

