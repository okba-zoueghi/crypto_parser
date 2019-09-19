project(CP_PARSER)

file(GLOB SOURCES
  "${PROJECT_SOURCE_DIR}/src/*.c"
)

include_directories(
	${PROJECT_SOURCE_DIR}/include/
)

add_library(sharedlib SHARED ${SOURCES})
add_library(staticlib STATIC ${SOURCES})

set_target_properties(sharedlib PROPERTIES OUTPUT_NAME cryptoparser)
set_target_properties(staticlib PROPERTIES OUTPUT_NAME cryptoparser)
