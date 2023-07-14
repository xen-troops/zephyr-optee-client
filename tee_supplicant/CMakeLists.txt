# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2023 EPAM Systems

add_library(TEE_SUPPLICANT INTERFACE)

target_include_directories(TEE_SUPPLICANT INTERFACE include)

zephyr_library()
zephyr_library_sources(src/tee_supplicant.c)
zephyr_library_sources(src/teec_ta_load.c)
zephyr_include_directories(include)
zephyr_include_directories(../public)
