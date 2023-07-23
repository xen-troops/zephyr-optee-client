/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef TEE_SUPPLICANT_H
#define TEE_SUPPLICANT_H

/* Helpers to access memref parts of a struct tee_param */
#define MEMREF_SHM_ID(p)          ((p)->c)
#define MEMREF_SHM_OFFS(p)        ((p)->a)
#define MEMREF_SIZE(p)            ((p)->b)
#define SET_MEMREF_SHM_ID(p, v)   ((p)->c = (v))
#define SET_MEMREF_SIZE(p, v)     ((p)->b = (v))

void *tee_param_get_mem(struct tee_param *param, size_t *size);

#endif /* TEE_SUPPLICANT_H */
