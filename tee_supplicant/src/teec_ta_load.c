/*
 * Copyright (c) 2014, STMicroelectronics International N.V.
 * Copyright (c) 2023, EPAM Systems
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/logging/log.h>
#include <teec_ta_load.h>

#define BINARY_PREFIX ta_load
#include <teec_trace.h>

LOG_MODULE_REGISTER(teec_ta_load);
static struct ta_table *ta_table;

void TEEC_SetTATable(struct ta_table *table)
{
	ta_table = table;
}

#define UUID_MAX_LEN 36

int TEECI_LoadSecureModule(const TEEC_UUID *destination, void *ta, size_t *ta_size)
{
	int res = TA_BINARY_NOT_FOUND;
	struct ta_table *t;
	char uuid[UUID_MAX_LEN + 1] = { 0 };

	if (!ta_table || !ta_size) {
		return TA_BINARY_NOT_FOUND;
	}

	snprintf(uuid, UUID_MAX_LEN + 1,
		     "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		     destination->timeLow,
		     destination->timeMid,
		     destination->timeHiAndVersion,
		     destination->clockSeqAndNode[0],
		     destination->clockSeqAndNode[1],
		     destination->clockSeqAndNode[2],
		     destination->clockSeqAndNode[3],
		     destination->clockSeqAndNode[4],
		     destination->clockSeqAndNode[5],
		     destination->clockSeqAndNode[6],
		     destination->clockSeqAndNode[7]);

	for (t = ta_table; t->uuid != NULL; t++) {
		if (!strncmp(uuid, t->uuid, UUID_MAX_LEN)) {
			if (ta && t->ta_size <= *ta_size) {
				memcpy(ta, t->ta_start, t->ta_size);
			}
			*ta_size = t->ta_size;
			res = TA_BINARY_FOUND;
			break;
		}
	}
	return res;
}
