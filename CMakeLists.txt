# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2023 EPAM Systems

zephyr_include_directories_ifdef(CONFIG_OPTEE_CLIENT public)
add_subdirectory_ifdef(CONFIG_OPTEE_LIBTEEC libteec)
add_subdirectory_ifdef(CONFIG_OPTEE_LIBCKTEEC libckteec)
add_subdirectory_ifdef(CONFIG_OPTEE_TEE_SUPPLICANT tee_supplicant)
