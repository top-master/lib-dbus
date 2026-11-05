# SPDX-FileCopyrightText: 2026 Ralf Habacker <ralf.habacker@freenet.de>
# SPDX-License-Identifier: MIT
#
# cmake consumer test: install dbus into a staging directory (DESTDIR) and
# build a small project against the installed DBus1 cmake package.

set(CONSUMER_DESTDIR "${PROJECT_BINARY_DIR}/consumer-install")
# the drive letter of an absolute Windows prefix cannot be appended to a path
string(REGEX REPLACE "^[A-Za-z]:" "" CONSUMER_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Settings of the main configure run the consumer build has to share.
# Cross compiling relies on the toolchain file, which is forwarded as well.
set(CONSUMER_OPTIONS
    -DCHECK_VERSION=${DBUS_VERSION_STRING}
    -DDBus1_DIR=${CONSUMER_DESTDIR}${CONSUMER_PREFIX}/${INSTALL_CMAKE_DIR}
)
set(CONSUMER_FORWARD CMAKE_TOOLCHAIN_FILE CMAKE_BUILD_TYPE CMAKE_GENERATOR_INSTANCE)
if(NOT CMAKE_GENERATOR MATCHES "^Visual Studio") # VS selects the compiler itself
    list(APPEND CONSUMER_FORWARD CMAKE_C_COMPILER)
endif()
foreach(var ${CONSUMER_FORWARD})
    if(${var})
        list(APPEND CONSUMER_OPTIONS -D${var}=${${var}})
    endif()
endforeach()

set(CONSUMER_GENERATOR --build-generator "${CMAKE_GENERATOR}")
if(CMAKE_GENERATOR_PLATFORM)
    list(APPEND CONSUMER_GENERATOR --build-generator-platform "${CMAKE_GENERATOR_PLATFORM}")
endif()
if(CMAKE_GENERATOR_TOOLSET)
    list(APPEND CONSUMER_GENERATOR --build-generator-toolset "${CMAKE_GENERATOR_TOOLSET}")
endif()

# multi-config generators (Visual Studio, Xcode) need an explicit config
if(CMAKE_CONFIGURATION_TYPES)
    set(CONSUMER_INSTALL_CONFIG --config $<CONFIG>)
    set(CONSUMER_BUILD_CONFIG --build-config $<CONFIG>)
endif()

add_test(NAME test-consumer-setup
    COMMAND ${CMAKE_COMMAND} -E env DESTDIR=${CONSUMER_DESTDIR}
            ${CMAKE_COMMAND} --install ${PROJECT_BINARY_DIR} ${CONSUMER_INSTALL_CONFIG}
)
add_test(NAME test-consumer-build
    COMMAND ${CMAKE_CTEST_COMMAND} --build-and-test
        ${CMAKE_CURRENT_SOURCE_DIR}/client-package
        ${CMAKE_CURRENT_BINARY_DIR}/client-package
        ${CONSUMER_BUILD_CONFIG}
        ${CONSUMER_GENERATOR}
        --build-makeprogram ${CMAKE_MAKE_PROGRAM}
        --build-options ${CONSUMER_OPTIONS} # must be the last option
)
add_test(NAME test-consumer-clean
    COMMAND ${CMAKE_COMMAND} -E remove_directory
        ${CONSUMER_DESTDIR} ${CMAKE_CURRENT_BINARY_DIR}/client-package
)
set_tests_properties(test-consumer-setup PROPERTIES FIXTURES_SETUP CONSUMER)
set_tests_properties(test-consumer-build PROPERTIES FIXTURES_REQUIRED CONSUMER)
set_tests_properties(test-consumer-clean PROPERTIES FIXTURES_CLEANUP CONSUMER)
