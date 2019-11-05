# CMakeFiles for 3rd vendor library

include(ExternalProject)

### OpenSSL 1.1.1
ExternalProject_Add(OpenSSL PREFIX openssl
        URL ${CMAKE_CURRENT_SOURCE_DIR}/openssl-1.1.1.tar.gz
        URL_MD5 d65944e4aa4de6ad9858e02c82d85183
        CONFIGURE_COMMAND ./Configure enable-ssl3 enable-ssl3-method enable-weak-ssl-ciphers linux-x86_64 --prefix=<INSTALL_DIR> --openssldir=<INSTALL_DIR>/lib/ssl
							enable-ec_nistp_64_gcc_128 no-shared
		BUILD_COMMAND ${MAKE_COMMAND}
		INSTALL_COMMAND make install_sw
        BUILD_IN_SOURCE 1)

ExternalProject_Get_Property(OpenSSL INSTALL_DIR)
set(OPENSSL_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
set(OPENSSL_LINK_DIRECTORIES ${INSTALL_DIR}/lib)
set(OPENSSL_PKGCONFIG_PATH ${INSTALL_DIR}/lib/pkgconfig/)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(openssl-crypto-static STATIC IMPORTED GLOBAL)
add_dependencies(openssl-crypto-static OpenSSL)
set_property(TARGET openssl-crypto-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libcrypto.a)
set_property(TARGET openssl-crypto-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

add_library(openssl-ssl-static STATIC IMPORTED GLOBAL)
add_dependencies(openssl-ssl-static OpenSSL)
set_property(TARGET openssl-ssl-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libssl.a)
set_property(TARGET openssl-ssl-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

### Libevent 2.1.8
ExternalProject_Add(libevent PREFIX libevent
        URL ${CMAKE_CURRENT_SOURCE_DIR}/libevent-2.1.8-stable.tar.gz
        URL_MD5 f3eeaed018542963b7d2416ef1135ecc
        CONFIGURE_COMMAND PKG_CONFIG_PATH=${OPENSSL_PKGCONFIG_PATH}
		                  ./configure --prefix=<INSTALL_DIR> --disable-shared --disable-samples
        BUILD_COMMAND make LDFLAGS="-ldl"
        BUILD_IN_SOURCE 1
		DEPENDS OpenSSL)

ExternalProject_Get_Property(libevent INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(libevent-static STATIC IMPORTED GLOBAL)
add_dependencies(libevent-static libevent)
set_property(TARGET libevent-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libevent.a)
set_property(TARGET libevent-static PROPERTY IMPORTED_INTERFACE_LINK_LIBRARIES pthread crypto)
set_property(TARGET libevent-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

### hiredis
ExternalProject_Add(hiredis PREFIX hiredis
        URL ${CMAKE_CURRENT_SOURCE_DIR}/hiredis-v0.14.0.tar.gz
		URL_MD5 b2c1b014d7bc7cf5ac3b64cc25359a78
		CONFIGURE_COMMAND ""
		BUILD_COMMAND make
        BUILD_IN_SOURCE 1)
		
ExternalProject_Get_Property(hiredis INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(hiredis-static STATIC IMPORTED GLOBAL)
add_dependencies(hiredis-static hiredis)
set_property(TARGET hiredis-static PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libhiredis.a)
set_property(TARGET hiredis-static PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

### libUUID 注意: --enable-shared --with-pic
ExternalProject_Add(libUUID PREFIX libUUID
        URL ${CMAKE_CURRENT_SOURCE_DIR}/libuuid-1.0.3.tar.gz
        URL_MD5 d44d866d06286c08ba0846aba1086d68
        CONFIGURE_COMMAND cd ../libUUID && ./configure --prefix=<INSTALL_DIR> --enable-shared --with-pic
        BUILD_COMMAND cd ../libUUID && make
        INSTALL_COMMAND cd ../libUUID && make install)

ExternalProject_Get_Property(libUUID INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(uuid SHARED IMPORTED GLOBAL)
add_dependencies(uuid libUUID)
set_property(TARGET uuid PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libuuid.a)
set_property(TARGET uuid PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

#### GoogleTest
ExternalProject_Add(googletest PREFIX googletest
        URL ${CMAKE_CURRENT_SOURCE_DIR}/googletest-release-1.8.0.tar.gz
        URL_MD5 16877098823401d1bf2ed7891d7dce36
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE})

ExternalProject_Get_Property(googletest INSTALL_DIR)
file(MAKE_DIRECTORY ${INSTALL_DIR}/include)

add_library(gtest STATIC IMPORTED GLOBAL)
add_dependencies(gtest googletest)
set_property(TARGET gtest PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libgtest.a)
set_property(TARGET gtest PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)
set_property(TARGET gtest PROPERTY INTERFACE_LINK_LIBRARIES pthread)

add_library(gmock STATIC IMPORTED GLOBAL)
add_dependencies(gmock googletest)
set_property(TARGET gmock PROPERTY IMPORTED_LOCATION ${INSTALL_DIR}/lib/libgmock.a)
set_property(TARGET gmock PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${INSTALL_DIR}/include)

### MESA Framework
# Consider the MESA Framework is installed in the system. We declare a imported target instead of
# ExternalProject target. we may retrive the MESAFramework source code from git.mesalab.cn and
# compile staticly to TFE binarys in the future.

set(MESA_FRAMEWORK_LIB_DIR /opt/MESA/lib)
set(MESA_FRAMEWORK_INCLUDE_DIR /opt/MESA/include)
set(MRZCPD_LIB_DIR /opt/mrzcpd/lib)
set(MRZCPD_INCLUDE_DIR /opt/mrzcpd/include)

add_library(MESA_handle_logger SHARED IMPORTED GLOBAL)
set_property(TARGET MESA_handle_logger PROPERTY IMPORTED_LOCATION ${MESA_FRAMEWORK_LIB_DIR}/libMESA_handle_logger.so)
set_property(TARGET MESA_handle_logger PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MESA_FRAMEWORK_INCLUDE_DIR})

add_library(MESA_prof_load SHARED IMPORTED GLOBAL)
set_property(TARGET MESA_prof_load PROPERTY IMPORTED_LOCATION ${MESA_FRAMEWORK_LIB_DIR}/libMESA_prof_load.so)
set_property(TARGET MESA_prof_load PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MESA_FRAMEWORK_INCLUDE_DIR})

add_library(wiredcfg SHARED IMPORTED GLOBAL)
set_property(TARGET wiredcfg PROPERTY IMPORTED_LOCATION ${MESA_FRAMEWORK_LIB_DIR}/libwiredcfg.so)
set_property(TARGET wiredcfg PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MESA_FRAMEWORK_INCLUDE_DIR})

add_library(MESA_htable SHARED IMPORTED GLOBAL)
set_property(TARGET MESA_htable PROPERTY IMPORTED_LOCATION ${MESA_FRAMEWORK_LIB_DIR}/libMESA_htable.so)
set_property(TARGET MESA_htable PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MESA_FRAMEWORK_INCLUDE_DIR})

add_library(wiredLB SHARED IMPORTED GLOBAL)
set_property(TARGET wiredLB PROPERTY IMPORTED_LOCATION ${MESA_FRAMEWORK_LIB_DIR}/libWiredLB.so)
set_property(TARGET wiredLB PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MESA_FRAMEWORK_INCLUDE_DIR})

add_library(maatframe SHARED IMPORTED GLOBAL)
set_property(TARGET maatframe PROPERTY IMPORTED_LOCATION ${MESA_FRAMEWORK_LIB_DIR}/libmaatframe.so)
set_property(TARGET maatframe PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MESA_FRAMEWORK_INCLUDE_DIR})

add_library(MESA_field_stat SHARED IMPORTED GLOBAL)
set_property(TARGET MESA_field_stat PROPERTY IMPORTED_LOCATION ${MESA_FRAMEWORK_LIB_DIR}/libMESA_field_stat2.so)
set_property(TARGET MESA_field_stat PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MESA_FRAMEWORK_INCLUDE_DIR})

add_library(librdkafka SHARED IMPORTED GLOBAL)
set_property(TARGET librdkafka PROPERTY IMPORTED_LOCATION ${MESA_FRAMEWORK_LIB_DIR}/librdkafka.so)
set_property(TARGET librdkafka PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MESA_FRAMEWORK_INCLUDE_DIR})

add_library(mrzcpd SHARED IMPORTED GLOBAL)
set_property(TARGET mrzcpd PROPERTY IMPORTED_LOCATION ${MRZCPD_LIB_DIR}/libmarsio.so)
set_property(TARGET mrzcpd PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${MRZCPD_INCLUDE_DIR})



