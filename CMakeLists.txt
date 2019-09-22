cmake_minimum_required(VERSION 3.13)

project(CP_PARSER C)

if(DEFINED C_CROSS_COMPILER)
  set(CMAKE_C_COMPILER ${C_CROSS_COMPILER})
  message(STATUS "Cross compiler is set to : ${C_CROSS_COMPILER}")
else()
  message(STATUS "Using default compiler : ${CMAKE_C_COMPILER}")
endif()

file(GLOB SOURCES
  "${PROJECT_SOURCE_DIR}/src/*.c"
)

include_directories(
	${PROJECT_SOURCE_DIR}/include/
)

link_directories(
  ${PROJECT_SOURCE_DIR}/build
)

add_library(sharedlib SHARED ${SOURCES})
add_library(staticlib STATIC ${SOURCES})

set_target_properties(sharedlib PROPERTIES OUTPUT_NAME cryptoparser)
set_target_properties(staticlib PROPERTIES OUTPUT_NAME cryptoparser)

add_subdirectory(samples)
