add_library(common syslogd/src/logging.cpp json/src/arraylist.c json/src/debug.c json/src/json_c_version.c
	json/src/json_object.c json/src/json_object_iterator.c json/src/json_tokener.c
	json/src/json_util.c json/src/libjson.c json/src/linkhash.c
	json/src/parse_flags.c json/src/printbuf.c json/src/json_checker.c json/src/random_seed.c
    rt/src/rt_stdlib.cpp rt/src/rt_string.cpp rt/src/rt_tmr.cpp rt/src/rt_time.cpp)

target_include_directories(common PUBLIC syslogd/include json/include rt/include)
target_link_libraries(common PUBLIC rt MESA_handle_logger breakpad_mini)
