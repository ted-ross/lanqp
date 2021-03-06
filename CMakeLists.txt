##
## Licensed to the Apache Software Foundation (ASF) under one
## or more contributor license agreements.  See the NOTICE file
## distributed with this work for additional information
## regarding copyright ownership.  The ASF licenses this file
## to you under the Apache License, Version 2.0 (the
## "License"); you may not use this file except in compliance
## with the License.  You may obtain a copy of the License at
## 
##   http://www.apache.org/licenses/LICENSE-2.0
## 
## Unless required by applicable law or agreed to in writing,
## software distributed under the License is distributed on an
## "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
## KIND, either express or implied.  See the License for the
## specific language governing permissions and limitations
## under the License.
##

project(lanqp C)
cmake_minimum_required(VERSION 2.6)
set(CMAKE_C_FLAGS "-pthread -Wall -Werror")

find_library(proton_lib qpid-proton)
find_path(proton_include proton/driver.h)
find_library(dispatch_lib qpid-dispatch)
find_path(dispatch_include qpid/dispatch/server.h)

# define the configuration directory based on whether or not the install prefix is defined
if(NOT DEFINED SYSCONF_INSTALL_DIR)
    if(CMAKE_INSTALL_PREFIX STREQUAL "/usr")
        set(SYSCONF_INSTALL_DIR "/etc")
    else()
        set(SYSCONF_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/etc")
    endif()
endif()

set(LANQP_CONFDIR ${SYSCONF_INSTALL_DIR})
set(DEFAULT_CONFIG_PATH "${LANQP_CONFDIR}/lanqp.conf" CACHE string "Default config file path")

include(CheckIncludeFiles)
check_include_files("linux/if_tun.h" HAVE_LINUX_IF_TUN_H)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

include_directories(
    ${CMAKE_CURRENT_BINARY_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${proton_include}
    ${dispatch_include}
    )

##
## Build the application
##
set(lanqp_SOURCES
    src/bridge.c
    src/main.c
    src/netns.c
    src/tun_dev.c
    )

add_executable(lanqp ${lanqp_SOURCES})
target_link_libraries(lanqp ${proton_lib} ${dispatch_lib})

