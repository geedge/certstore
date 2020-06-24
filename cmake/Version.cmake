
# Using autorevision.sh to generate version information

set(__SOURCE_AUTORESIVISION ${CMAKE_SOURCE_DIR}/autorevision.sh)
set(__AUTORESIVISION ${CMAKE_BINARY_DIR}/autorevision.sh)
set(__VERSION_CACHE ${CMAKE_SOURCE_DIR}/version.txt)
set(__VERSION_CONFIG ${CMAKE_BINARY_DIR}/version.cmake)

file(COPY ${__SOURCE_AUTORESIVISION} DESTINATION ${CMAKE_BINARY_DIR}
	FILE_PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE GROUP_READ GROUP_EXECUTE
	WORLD_READ WORLD_EXECUTE)

# execute autorevision.sh to generate version information
execute_process(COMMAND ${__AUTORESIVISION} -t cmake -o ${__VERSION_CACHE} OUTPUT_FILE ${__VERSION_CONFIG})
include(${__VERSION_CONFIG})

# extract major, minor, patch version from git tag
string(REGEX REPLACE "^v([0-9]+)\\..*" "\\1" TARGET_MAJOR "${VCS_TAG}")
string(REGEX REPLACE "^v[0-9]+\\.([0-9]+).*" "\\1" TARGET_MINOR "${VCS_TAG}")
string(REGEX REPLACE "^v[0-9]+\\.[0-9]+\\.([0-9]+).*" "\\1" TARGET_PATCH "${VCS_TAG}")
string(REGEX MATCH  "[^-]*$" TARGET_TAGS "${VCS_TAG}")

if(TARGET_TAGS)
    set(TARGET_PATCH ${TARGET_PATCH}.${TARGET_TAGS})
endif()

if(NOT TARGET_MAJOR)
    set(TARGET_MAJOR 1)
endif()

if(NOT TARGET_MINOR)
    set(TARGET_MINOR 0)
endif()

if(NOT TARGET_PATCH)
    set(TARGET_PATCH 0)
endif()

set(TARGET_DESCRIBE "${VCS_SHORT_HASH}")
set(TARGET_VERSION "${TARGET_MAJOR}.${TARGET_MINOR}.${TARGET_PATCH}-${TARGET_DESCRIBE}")
set(TARGET_GIT_VERSION "${TARGET_MAJOR}.${TARGET_MINOR}.${TARGET_PATCH}-${TARGET_DESCRIBE}")

# Replace .- with _
string(REGEX REPLACE "[\\.\\-]" "_" TARGET_VAR_VERSION "${TARGET_GIT_VERSION}")

# print information
message(STATUS "Welcome to Certstore, Version: ${TARGET_VERSION}")
add_definitions(-DTARGET_GIT_VERSION=\"${TARGET_GIT_VERSION}\")
add_definitions(-DTARGET_VAR_VERSION=${TARGET_VAR_VERSION})
