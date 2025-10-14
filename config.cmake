set(PROJECT_NAME "simple-port-forwarder")
set(PROJECT_VERSION "1.0.0")
set(PROJECT_DESCRIPTION "Simple Port Forwarder")
set(PROJECT_LANGUAGE "C")

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Common compiler flags
set(STANDARD_FLAGS
        -D_POSIX_C_SOURCE=200809L
        -D_XOPEN_SOURCE=700
        #-D_GNU_SOURCE
        #-D_DARWIN_C_SOURCE
        #-D__BSD_VISIBLE
        -Werror
)

# Define targets
set(EXECUTABLE_TARGETS main)
set(LIBRARY_TARGETS "")

set(main_SOURCES
        src/main.c
        src/convert.c
        src/server.c
)

set(main_HEADERS
        include/convert.h
        include/server.h
)

set(main_LINK_LIBRARIES
        p101_error
        p101_env
        p101_c
        p101_posix
        p101_fsm
        p101_unix
        m
        iconv
        )

