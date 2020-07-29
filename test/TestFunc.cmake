set(SYSROOT ${CMAKE_CURRENT_SOURCE_DIR}/../../sysroot)

set(CLANG clang-3.9) # work only clang-3.9 and clang-4.0
set(CFLAGS_BC -fno-vectorize -fno-slp-vectorize -emit-llvm -target le32-unknown-nacl
	--sysroot=${SYSROOT} -I${SYSROOT}/usr/include -I${CMAKE_CURRENT_SOURCE_DIR} -std=gnu99
	)

function(BuildFile a_OutFile a_InputFile a_Oprimization a_Index)
	set(OUT_FILE
			${CMAKE_CURRENT_BINARY_DIR}/build-O${a_Oprimization}/${a_InputFile}.bc
			)
	set(${a_OutFile} ${OUT_FILE} PARENT_SCOPE)
	
	get_filename_component(OUT_FILE_DIR ${OUT_FILE} DIRECTORY)
	get_filename_component(OUT_FILE_NAME ${OUT_FILE} NAME)
	
	add_custom_command(
		OUTPUT ${OUT_FILE}
		COMMAND mkdir -p ${OUT_FILE_DIR}
		COMMAND ${CLANG} -O0 ${CFLAGS_BC} -c ${CMAKE_CURRENT_SOURCE_DIR}/${a_InputFile} -o ${OUT_FILE}
		COMMENT "Compile ${SRCS_TEST_C_FILE}"
	)
	
	add_custom_target(${OUT_FILE_NAME}_${a_Index}_${a_Oprimization} ALL DEPENDS ${OUT_FILE})
endfunction()

function(BuildFile_AndTest a_FileName a_Oprimization a_Index)
	BuildFile(OUT_FILE ${a_FileName} ${a_Oprimization} ${a_Index})

	add_test(NAME test_${INDEX}_${a_FileName}_${a_Oprimization} 
		COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../../vmir ${OUT_FILE}
		)
endfunction()

function(BuildFile_AndRegressTest a_FileName a_Oprimization a_Index)
	BuildFile(OUT_FILE ${a_FileName} ${a_Oprimization} ${a_Index})

	add_test(NAME test_${INDEX}_${a_FileName}_${a_Oprimization} 
		COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/../run_regress_test ${CMAKE_CURRENT_SOURCE_DIR}/../../vmir ${OUT_FILE} ${CMAKE_CURRENT_SOURCE_DIR}/${a_FileName}.expected
		)
endfunction()

function(BuildVmirTest a_InputFileTemplate)
	file(GLOB SRCS_TEST_C_FILES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ${a_InputFileTemplate}) #_RECURSE
	
	set(INDEX 0)
	
	foreach(SRCS_TEST_C_FILE ${SRCS_TEST_C_FILES})
		math(EXPR INDEX "${INDEX} + 1")
		
		BuildFile_AndTest(${SRCS_TEST_C_FILE} 0 ${INDEX})
	
		BuildFile_AndTest(${SRCS_TEST_C_FILE} 1 ${INDEX})
	
		BuildFile_AndTest(${SRCS_TEST_C_FILE} 2 ${INDEX})
	endforeach()
endfunction()

function(BuildRegressTest a_InputFileTemplate)
	file(GLOB SRCS_TEST_C_FILES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ${a_InputFileTemplate}) #_RECURSE
	
	set(INDEX 0)
	
	foreach(SRCS_TEST_C_FILE ${SRCS_TEST_C_FILES})
		math(EXPR INDEX "${INDEX} + 1")
		
		BuildFile_AndRegressTest(${SRCS_TEST_C_FILE} 0 ${INDEX})
	
		BuildFile_AndRegressTest(${SRCS_TEST_C_FILE} 1 ${INDEX})
	
		BuildFile_AndRegressTest(${SRCS_TEST_C_FILE} 2 ${INDEX})
	endforeach()
endfunction()
