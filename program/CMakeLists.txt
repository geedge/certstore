if(COMMAND cmake_policy)
	cmake_policy(SET CMP0003 NEW)
endif(COMMAND cmake_policy)

add_executable(certstore src/cert_store.cpp src/cert_conf.cpp src/cert_session.cpp)

target_include_directories(certstore PRIVATE ${CMAKE_CURRENT_LIST_DIR}/include)
target_include_directories(certstore PRIVATE ${SYSTEMD_INCLUDE_DIRS})

target_link_libraries(certstore dl common
		maatframe 
		openssl-ssl-static
		openssl-crypto-static
		pthread
		uuid
		libevent-static
		MESA_htable
		MESA_prof_load
		MESA_handle_logger
		hiredis-static
		MESA_field_stat
		${SYSTEMD_LIBRARIES})
