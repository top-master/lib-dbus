# SPDX-FileCopyrightText: 2026 Ralf Habacker <ralf.habacker@freenet.de>
# SPDX-License-Identifier: MIT

cmake_minimum_required(VERSION 3.10)

project(DBus1test LANGUAGES C)

find_package(DBus1 CONFIG REQUIRED)

if(NOT CHECK_VERSION)
    message(FATAL_ERROR "CHECK_VERSION is not set")
endif()

if(NOT DBus1_VERSION VERSION_EQUAL CHECK_VERSION)
    message(FATAL_ERROR "version mismatch: found '${DBus1_VERSION}', expected '${CHECK_VERSION}'")
endif()

add_executable(mytest test.c)
target_link_libraries(mytest PRIVATE dbus-1)

# the public headers should compile cleanly
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(mytest PRIVATE -Wall -Wformat -Werror)
elseif(MSVC)
    target_compile_options(mytest PRIVATE /W3 /WX)
endif()
