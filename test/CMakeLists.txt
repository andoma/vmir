cmake_minimum_required(VERSION 3.10)
project(test
	DESCRIPTION "test project"
)

enable_testing()
add_subdirectory(gcc-torture)
add_subdirectory(misc)
add_subdirectory(regress)
