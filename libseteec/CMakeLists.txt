# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2023 EPAM Systems
# Author: Dmytro Semenets <dmytro_semenets@epam.com>

add_library(OPTEE_LIBSETEEC INTERFACE)

target_include_directories(OPTEE_LIBSETEEC INTERFACE include)

zephyr_library()
zephyr_library_sources(src/se.c)
zephyr_library_link_libraries(OPTEE_LIBSETEEC)
zephyr_include_directories(include)
