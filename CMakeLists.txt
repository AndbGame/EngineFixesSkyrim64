cmake_minimum_required(VERSION 3.30)

if(POLICY CMP0167)
  cmake_policy(SET CMP0167 NEW)
endif()

macro(set_from_environment VARIABLE)
	if (NOT DEFINED ${VARIABLE} AND DEFINED ENV{${VARIABLE}})
		set(${VARIABLE} $ENV{${VARIABLE}})
	endif ()
endmacro()

include(cmake/version.cmake)

project(
	EngineFixes
	VERSION ${VERSION}
	LANGUAGES C CXX
)

add_compile_definitions(SKYRIM)
set(CommonLibPath "external/CommonLibSSE-NG")
set(CommonLibName "CommonLibSSE")
set(GameVersion "Skyrim")

configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake/Version.h.in"
	"${CMAKE_CURRENT_BINARY_DIR}/include/Version.h"
	@ONLY
)

configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.rc.in"
	"${CMAKE_CURRENT_BINARY_DIR}/version.rc"
	@ONLY
)

if(PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
	message(FATAL_ERROR "in-source builds are not allowed")
endif()

add_compile_definitions(
	SKSE_SUPPORT_XBYAK
    _UNICODE
    UNICODE
)

add_subdirectory(${CommonLibPath} ${CommonLibName} EXCLUDE_FROM_ALL)

find_package(spdlog CONFIG REQUIRED)
find_package(AutoTOML REQUIRED CONFIG)
find_package(boost_regex CONFIG REQUIRED)
find_package(TBB
	REQUIRED
	CONFIG
	COMPONENTS
		tbb
	CONFIG
)
find_package(xbyak REQUIRED CONFIG)

include(cmake/sourcelist.cmake)

source_group(
	TREE ${CMAKE_CURRENT_SOURCE_DIR}
	FILES ${SOURCES}
)

source_group(
	TREE ${CMAKE_CURRENT_BINARY_DIR}
	FILES ${CMAKE_CURRENT_BINARY_DIR}/include/Version.h
)

add_library(
	${PROJECT_NAME}
	SHARED
	${SOURCES}
	external/rpmalloc/rpmalloc/rpmalloc.c
	${CMAKE_CURRENT_BINARY_DIR}/include/Version.h
	${CMAKE_CURRENT_BINARY_DIR}/version.rc
	${PROJECT_NAME}.toml
	.clang-format
	.editorconfig
)

# TODO: flags
set_source_files_properties( external/rpmalloc/rpmalloc/rpmalloc.c PROPERTIES COMPILE_FLAGS "/D \"_UNICODE\" /D \"UNICODE\" /std:c17 /Zi /Oi /Oy- /GS- /Qpar- /fp:fast /fp:except- /Zc:forScope /Zc:wchar_t /GR- /openmp- /W4 /WX /wd4201 /wd4100 /Gm- /Ob2 /Ot /GT /GL /GF /O2 /D\"BUILD_RELEASE=1\"")

target_compile_features(
	${PROJECT_NAME}
	PRIVATE
		cxx_std_23
)

target_include_directories(
	${PROJECT_NAME}
	PRIVATE
		${CMAKE_CURRENT_BINARY_DIR}/include
		${CMAKE_CURRENT_SOURCE_DIR}/src
		"external/rpmalloc/rpmalloc"
)

target_link_libraries(
	${PROJECT_NAME}
	PRIVATE
		AutoTOML::AutoTOML
		Boost::regex
		CommonLibSSE::CommonLibSSE
		TBB::tbb
		xbyak::xbyak
#		${CMAKE_CURRENT_SOURCE_DIR}/external/rpmalloc/lib/windows/release/x86-64/rpmalloc.lib
)
target_compile_definitions(
	${PROJECT_NAME}
	PRIVATE
		ENABLE_PRELOAD
		ENABLE_VALIDATE_ARGS
		ENABLE_ASSERTS
		ENABLE_THREAD_CACHE=1
#		ENABLE_STATISTICS
)

if (MSVC)
	target_link_options(
		${PROJECT_NAME}
		PRIVATE
			"$<$<CONFIG:DEBUG>:/INCREMENTAL;/OPT:NOREF;/OPT:NOICF>"
			"$<$<CONFIG:RELEASE>:/INCREMENTAL:NO;/OPT:REF;/OPT:ICF;/DEBUG:FULL>"
	)
endif()

target_precompile_headers(
	${PROJECT_NAME}
	PRIVATE
	"$<$<COMPILE_LANGUAGE:CXX>:${CMAKE_CURRENT_SOURCE_DIR}/src/PCH.h>"
)

option(COPY_BUILD "whether we should copy the outputs to the skyrim dir" OFF)
if(COPY_BUILD)
    set_from_environment(Skyrim64Path)
    if (DEFINED Skyrim64Path)
        add_custom_command(
            TARGET ${PROJECT_NAME}
            POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_FILE:${PROJECT_NAME}>" ${Skyrim64Path}/Data/SKSE/Plugins/
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "$<TARGET_PDB_FILE:${PROJECT_NAME}>" ${Skyrim64Path}/Data/SKSE/Plugins/
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_SOURCE_DIR}/${PROJECT_NAME}_preload.txt" ${Skyrim64Path}/Data/SKSE/Plugins/
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_SOURCE_DIR}/${PROJECT_NAME}_SNCT.toml" ${Skyrim64Path}/Data/SKSE/Plugins/
            COMMAND ${CMAKE_COMMAND} -E copy_if_different "${CMAKE_SOURCE_DIR}/${PROJECT_NAME}.toml" ${Skyrim64Path}/Data/SKSE/Plugins/
        )
    else()
        message(WARNING "Skyrim64Path is not defined: skipping post-build copy")
    endif()
endif()

set(Python3_FIND_STRATEGY "VERSION")
find_package(Python3
	MODULE
	REQUIRED
	COMPONENTS
		Interpreter
)

if(TARGET Python3::Interpreter)
	set(SCRIPT ${CMAKE_CURRENT_SOURCE_DIR}/scripts/archive_artifacts.py)
	set(TARGET_NAME "archive")

	add_custom_target(
		${TARGET_NAME}
		COMMAND
			"$<TARGET_FILE:Python3::Interpreter>"
			"${SCRIPT}"
			"--dll=$<TARGET_FILE:${PROJECT_NAME}>"
			"--name=${PROJECT_NAME}"
			"--out-dir=${TARGET_NAME}"
			"--pdb=$<TARGET_PDB_FILE:${PROJECT_NAME}>"
			"--src-dir=${CMAKE_CURRENT_SOURCE_DIR}"
		WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
		VERBATIM
		SOURCES
			${SCRIPT}
	)

	add_dependencies(${TARGET_NAME} ${PROJECT_NAME})
else()
	message(WARNING "failed to find python interpreter: skipping archive target")
endif()
