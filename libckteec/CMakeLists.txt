# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2023 EPAM Systems
# Author: Dmytro Semenets <dmytro_semenets@epam.com>

add_library(OPTEE_LIBCKTEEC INTERFACE)

target_include_directories(OPTEE_LIBCKTEEC INTERFACE include)

zephyr_library()
zephyr_library_sources(src/ck_debug.c)
zephyr_library_sources(src/ck_helpers.c)
zephyr_library_sources(src/invoke_ta.c)
zephyr_library_sources(src/pkcs11_api.c)
zephyr_library_sources(src/pkcs11_processing.c)
zephyr_library_sources(src/pkcs11_token.c)
zephyr_library_sources(src/serialize_ck.c)
zephyr_library_sources(src/serializer.c)
zephyr_library_link_libraries(OPTEE_LIBCKTEEC)
zephyr_include_directories(include)
