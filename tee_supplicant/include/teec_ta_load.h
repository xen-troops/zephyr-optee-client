/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef _TEEC_TA_LOAD_H
#define _TEEC_TA_LOAD_H
#include <tee_client_api.h>

#define TA_BINARY_FOUND 0
#define TA_BINARY_NOT_FOUND -1

/**
 * Based on the uuid this function will try to find a TA-binary on the
 * filesystem and return it back to the caller in the parameter ta.
 *
 * @param: destination  The uuid of the TA we are searching for.
 * @param: ta           A pointer which this function will copy
 *                      the TA from the filesystem to if *@ta_size i large
 *                      enough.
 * @param: ta_size      The size of the TA found on file system. It will be 0
 *                      if no TA was not found.
 *
 * @return              0 if TA was found, otherwise -1.
 */

int TEECI_LoadSecureModule(const TEEC_UUID *destination, void *ta,
			   size_t *ta_size);

struct ta_table {
	char *uuid;
	unsigned char *ta_start;
	size_t ta_size;
};

/**
 * Setting lookup table for searching ta
 *
 * @param: table        pointer to lookup table.
 *
 * @return              0 if TA was found, otherwise -1.
 */
void TEEC_SetTATable(struct ta_table *table);
#endif
