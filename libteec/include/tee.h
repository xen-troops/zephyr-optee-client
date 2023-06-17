/*
 * Copyright (c) 2015-2016, Linaro Limited
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

#ifndef __TEE_H
#define __TEE_H

#include <stdint.h>

#ifndef _GID_T_DECLARED
typedef unsigned short gid_t;
#define _GID_T_DECLARED
#endif

/*
 * This file describes the API provided by a TEE driver to user space.
 *
 * Each TEE driver defines a TEE specific protocol which is used for the
 * data passed back and forth using TEE_IOC_CMD.
 */

/* Helpers to make the ioctl defines */
#define TEE_IOC_MAGIC	0xa4
#define TEE_IOC_BASE	0

/* Flags relating to shared memory */
#define TEE_SHM_MAPPED	0x1	/* memory mapped in normal world */
#define TEE_SHM_DMA_BUF	0x2	/* dma-buf handle on shared memory */

#define TEE_MAX_ARG_SIZE	1024
#define TEE_MEMREF_NULL		((uint64_t)-1) /* NULL MemRef Buffer */

/*
 * TEE Implementation ID
 */
#define TEE_IMPL_ID_OPTEE	1
#define TEE_IMPL_ID_AMDTEE	2

/*
 * OP-TEE specific capabilities
 */
#define TEE_OPTEE_CAP_TZ	(1 << 0)

/*
 * Attributes for struct tee_param, selects field in the union
 */
#define TEE_PARAM_ATTR_TYPE_NONE		0	/* parameter not used */

/* These defines value parameters (struct tee_param_value) */
#define TEE_PARAM_ATTR_TYPE_VALUE_INPUT	1
#define TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT	2
#define TEE_PARAM_ATTR_TYPE_VALUE_INOUT	3	/* input and output */
/*
 * These defines shared memory reference parameters
 */
#define TEE_PARAM_ATTR_TYPE_MEMREF_INPUT	5
#define TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT	6
#define TEE_PARAM_ATTR_TYPE_MEMREF_INOUT	7	/* input and output */

/*
 * Mask for the type part of the attribute, leaves room for more types
 */
#define TEE_PARAM_ATTR_TYPE_MASK		0xff

/* Meta parameter carrying extra information about the message. */
#define TEE_PARAM_ATTR_META		0x100

/* Mask of all known attr bits */
#define TEE_PARAM_ATTR_MASK (TEE_PARAM_ATTR_TYPE_MASK | TEE_PARAM_ATTR_META)

/*
 * Matches TEEC_LOGIN_* in GP TEE Client API
 * Are only defined for GP compliant TEEs
 */
#define TEE_LOGIN_PUBLIC			0
#define TEE_LOGIN_USER			1
#define TEE_LOGIN_GROUP			2
#define TEE_LOGIN_APPLICATION		4
#define TEE_LOGIN_USER_APPLICATION	5
#define TEE_LOGIN_GROUP_APPLICATION	6

#define TEE_UUID_LEN		16

#endif /*__TEE_H*/
