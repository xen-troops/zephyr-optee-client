# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2023 EPAM Systems
# Author: Dmytro Semenets <dmytro_semenets@epam.com>

add_library(OPTEE_LIBTEEC INTERFACE)

target_include_directories(OPTEE_LIBTEEC INTERFACE include)

zephyr_library()
zephyr_library_sources(src/tee_client_api.c)
zephyr_library_link_libraries(OPTEE_LIBTEEC)
zephyr_include_directories(include)
