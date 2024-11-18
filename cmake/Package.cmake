if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CPACK_PACKAGE_NAME "certstore-debug")
else()
    set(CPACK_PACKAGE_NAME "certstore")
endif()

set(CPACK_PACKAGE_VENDOR "MESASOFT")
set(CMAKE_INSTALL_PREFIX "/opt/tsg/certstore")
set(CPACK_PACKAGE_VERSION_MAJOR "${TARGET_MAJOR}")
set(CPACK_PACKAGE_VERSION_MINOR "${TARGET_MINOR}")
set(CPACK_PACKAGE_VERSION_PATCH "${TARGET_PATCH}.${TARGET_DESCRIBE}")
set(CPACK_PACKAGING_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# RPM Build
set(CPACK_GENERATOR "RPM")
set(CPACK_RPM_AUTO_GENERATED_FILE_NAME ON)
set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")
set(CPACK_RPM_PACKAGE_AUTOREQPROV "no")
set(CPACK_RPM_PACKAGE_RELEASE_DIST on)
set(CPACK_RPM_DEBUGINFO_PACKAGE on)

set(CPACK_RPM_BUILD_SOURCE_DIRS_PREFIX /home/tsg)

install(PROGRAMS build/program/certstore DESTINATION ./bin)
install(DIRECTORY resource/cert DESTINATION ./) 
install(DIRECTORY resource/conf DESTINATION ./)

install(FILES script/tool/signssl.sh DESTINATION ./tool)
install(FILES script/tool/x509 DESTINATION ./tool)

install(FILES script/service/certstore.service DESTINATION /usr/lib/systemd/system/)
install(FILES script/tmpfiles/cert_store.conf DESTINATION /usr/lib/tmpfiles.d/)

# Must uninstall the debug package before install release package
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CPACK_RPM_PACKAGE_CONFLICTS "certostre")
else()
    set(CPACK_RPM_PACKAGE_CONFLICTS "certostre-debug")
endif()

# setup %config(noreplace)
set(CPACK_RPM_USER_FILELIST "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/conf/cert_store.ini"
			    "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/conf/table_info.conf"
                            "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/conf/pxy_obj_keyring.json")
include(CPack)
