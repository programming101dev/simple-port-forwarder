cmake_minimum_required(VERSION 3.14)
project(simple_port_forwarder_tests C)
enable_testing()

option(P101_TEST_COVERAGE "Instrument the code under test" OFF)
set(_COV "")
if(P101_TEST_COVERAGE)
    set(_COV --coverage)
endif()

set(P101_LIBS
        p101_error
        p101_env
        p101_c
        p101_filesystem
        p101_fsm
        p101_io
        p101_network
        p101_random
        p101_sync
        p101_thread
        p101_time)
set(P101_PUBLIC_INCLUDE_DIRS "" CACHE STRING "Extra p101 include dirs")
set(P101_PUBLIC_LINK_DIRS "" CACHE STRING "Extra p101 link dirs")
separate_arguments(P101_PUBLIC_INCLUDE_DIRS_LIST NATIVE_COMMAND "${P101_PUBLIC_INCLUDE_DIRS}")
separate_arguments(P101_PUBLIC_LINK_DIRS_LIST NATIVE_COMMAND "${P101_PUBLIC_LINK_DIRS}")
set(_P101_INC_DIRS ${P101_PUBLIC_INCLUDE_DIRS_LIST} /usr/local/include /opt/homebrew/include /opt/local/include)
set(_P101_LIB_DIRS ${P101_PUBLIC_LINK_DIRS_LIST} /usr/local/lib /usr/local/lib64 /opt/homebrew/lib /opt/local/lib)

set(_P101_RESOLVED "")
foreach(_library IN LISTS P101_LIBS)
    unset(_P101_LIB_${_library} CACHE)
    unset(_P101_LIB_${_library})
    find_library(_P101_LIB_${_library} NAMES ${_library} PATHS ${_P101_LIB_DIRS} NO_DEFAULT_PATH)
    if(NOT _P101_LIB_${_library})
        find_library(_P101_LIB_${_library} NAMES ${_library})
    endif()
    if(NOT _P101_LIB_${_library})
        message(FATAL_ERROR "Required p101 library '${_library}' was not found")
    endif()
    list(APPEND _P101_RESOLVED "${_P101_LIB_${_library}}")
endforeach()

find_package(Threads REQUIRED)

add_executable(test_forwarding
        test_forwarding.c
        ../src/server_connection.c
        ../src/server_settings.c
        ../src/server_state.c)
target_compile_definitions(test_forwarding PRIVATE SIMPLE_PORT_FORWARDER_TESTING=1)
target_include_directories(test_forwarding PRIVATE ${_P101_INC_DIRS} "${CMAKE_CURRENT_SOURCE_DIR}/../include")
target_link_libraries(test_forwarding PRIVATE ${_P101_RESOLVED} Threads::Threads m)
target_compile_options(test_forwarding PRIVATE ${_COV})
target_link_options(test_forwarding PRIVATE ${_COV})
add_test(NAME forwarding COMMAND test_forwarding)
