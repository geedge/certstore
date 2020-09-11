cmake_minimum_required(VERSION 3.5)
project(certstore)

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
set(CMAKE_SCRIPT_PATH ${PROJECT_SOURCE_DIR}/script)
include(Version)
include(Package)

add_definitions(-D_GNU_SOURCE)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 11)

if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE RelWithDebInfo)
endif()

if (CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set (CMAKE_INSTALL_PREFIX "/opt/tsg/certstore" CACHE PATH "default install path" FORCE )
endif()

# Global compile options
option(ENABLE_PIC "Generate position independent code (necessary for shared libraries)" TRUE)
option(ENABLE_WARNING_ALL "Enable all optional warnings which are desirable for normal code" TRUE)
option(ENABLE_SANITIZE_ADDRESS "Enable AddressSanitizer" FALSE)
option(ENABLE_SANITIZE_THREAD "Enable ThreadSanitizer" FALSE)

if(ENABLE_WARNING_ALL)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
endif()

if(ENABLE_SANITIZE_ADDRESS)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address -fno-omit-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
elseif(ENABLE_SANITIZE_THREAD)
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=thread -fno-omit-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread -fno-omit-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
endif()

if(ENABLE_SANITIZE_ADDRESS AND ENABLE_SANITIZE_THREAD)
	message(WARNING "Both ENABLE_SANITIZE_ADDRESS and ENABLE_SANITIZE_THREAD set, only ENABLE_SANITIZE_ADDRESS effected.")
endif()

add_custom_target("install-program" COMMAND ${CMAKE_COMMAND} ARGS -DCOMPONENT=Program -P cmake_install.cmake)
add_custom_target("install-profile" COMMAND ${CMAKE_COMMAND} ARGS -DCOMPONENT=Profile -P cmake_install.cmake)
add_custom_target("tarball" COMMAND sh ${CMAKE_SCRIPT_PATH}/tarball.sh ${TARGET_VERSION} ${TARGET_DESCRIBE})

enable_testing()
add_subdirectory(vendor)
add_subdirectory(common)
add_subdirectory(program)
