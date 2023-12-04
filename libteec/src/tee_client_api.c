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

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <zephyr/device.h>
#include <zephyr/drivers/tee.h>
#include <zephyr/kernel.h>
#include <zephyr/xen/generic.h>
#include <zephyr/logging/log.h>
#include <tee_client_api_extensions.h>
#include <tee_client_api.h>

LOG_MODULE_REGISTER(tee_client_api);

#ifndef __aligned
#define __aligned(size) __attribute__((__aligned__(size)))
#endif

#include <tee.h>

#define DT_COMPATIBLE linaro_optee_tz

/* How many device sequence numbers will be tried before giving up */
#define TEEC_MAX_DEV_SEQ	10

/* Helpers to access memref parts of a struct tee_ioctl_param */
#define MEMREF_SHM_ID(p)	((p)->c)
#define MEMREF_SHM_OFFS(p)	((p)->a)
#define MEMREF_SIZE(p)		((p)->b)

/*
 * Internal flags of TEEC_SharedMemory::internal.flags
 */
#define SHM_FLAG_BUFFER_ALLOCED		(1u << 0)
#define SHM_FLAG_SHADOW_BUFFER_ALLOCED	(1u << 1)

static K_MUTEX_DEFINE(teec_mutex);

static void teec_mutex_lock(struct k_mutex  *mu)
{
	k_mutex_lock(mu, K_FOREVER);
}

static void teec_mutex_unlock(struct k_mutex  *mu)
{
	k_mutex_unlock(mu);
}

static void *teec_paged_aligned_alloc(size_t sz)
{
	return k_aligned_alloc(XEN_PAGE_SIZE, sz);
}

static int teec_open_dev(struct device const **dev, const char *capabilities,
			 uint32_t *gen_caps)
{
	struct tee_version_info info;
	int ret;

	memset(&info, 0, sizeof(info));
	*dev = DEVICE_DT_GET_ONE(DT_COMPATIBLE);
	ret = tee_get_version(*dev, &info);
	if (ret) {
		return -1;
	}

	/* We can only handle GP TEEs */
	if (!(info.gen_caps & TEE_GEN_CAP_GP)) {
		return -1;
	}

	if (capabilities) {
		if (strcmp(capabilities, "optee-tz") == 0) {
			if (info.impl_id != TEE_IMPL_ID_OPTEE) {
				return -1;
			}
			if (!(info.impl_caps & TEE_OPTEE_CAP_TZ)) {
				return -1;
			}
		} else {
			/* Unrecognized capability requested */
			return -1;
		}
	}

	*gen_caps = info.gen_caps;
	return 0;
}

static struct tee_shm *teec_shm_alloc(const struct device *dev, size_t size, uint32_t flags)
{
	struct tee_shm *p;
	int ret;

	ret = tee_shm_alloc(dev, size, flags, &p);
	if (ret < 0)
		return NULL;
	return p;
}

static int teec_shm_register(const struct device *dev, void *buf, size_t size, uint32_t flags,
			     struct tee_shm **shm)
{
	int ret;

	ret = tee_shm_register(dev, buf, size, flags, shm);
	return ret;
}

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *ctx)
{
	uint32_t gen_caps = 0;
	int ret;

	if (!ctx)
		return TEEC_ERROR_BAD_PARAMETERS;

	ret = teec_open_dev(&ctx->dev, name, &gen_caps);
	if (!ret) {
		ctx->reg_mem = gen_caps & TEE_GEN_CAP_REG_MEM;
		ctx->memref_null = gen_caps & TEE_GEN_CAP_MEMREF_NULL;
		return TEEC_SUCCESS;
	}

	return TEEC_ERROR_ITEM_NOT_FOUND;
}

void TEEC_FinalizeContext(TEEC_Context *ctx)
{
}

static TEEC_Result teec_pre_process_tmpref(TEEC_Context *ctx,
			uint32_t param_type, TEEC_TempMemoryReference *tmpref,
			struct tee_param *param,
			TEEC_SharedMemory *shm)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;

	switch (param_type) {
		case TEEC_MEMREF_TEMP_INPUT:
			param->attr = TEE_PARAM_ATTR_TYPE_MEMREF_INPUT;
			shm->flags = TEEC_MEM_INPUT;
			break;
		case TEEC_MEMREF_TEMP_OUTPUT:
			param->attr = TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
			shm->flags = TEEC_MEM_OUTPUT;
			break;
		case TEEC_MEMREF_TEMP_INOUT:
			param->attr = TEE_PARAM_ATTR_TYPE_MEMREF_INOUT;
			shm->flags = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
			break;
		default:
			return TEEC_ERROR_BAD_PARAMETERS;
	}
	shm->size = tmpref->size;

	if (!tmpref->buffer) {
		if (tmpref->size)
			return TEEC_ERROR_BAD_PARAMETERS;

		if (ctx->memref_null) {
			/* Null pointer, indicate no shared memory attached */
			MEMREF_SHM_ID(param) = TEE_MEMREF_NULL;
			shm->id = -1;
		} else {
			res = TEEC_AllocateSharedMemory(ctx, shm);
			if (res != TEEC_SUCCESS)
				return res;
			MEMREF_SHM_ID(param) = shm->id;
		}
	} else {
		shm->buffer = tmpref->buffer;
		res = TEEC_RegisterSharedMemory(ctx, shm);
		if (res != TEEC_SUCCESS)
			return res;

		if (shm->shadow_buffer)
			memcpy(shm->shadow_buffer, tmpref->buffer, tmpref->size);

		MEMREF_SHM_ID(param) = shm->id;
	}

	MEMREF_SIZE(param) = tmpref->size;

	return TEEC_SUCCESS;
}

static TEEC_Result teec_pre_process_whole(TEEC_RegisteredMemoryReference *memref,
					  struct tee_param *param)
{
	const uint32_t inout = TEEC_MEM_INPUT | TEEC_MEM_OUTPUT;
	uint32_t flags = memref->parent->flags & inout;
	TEEC_SharedMemory *shm = NULL;

	if (flags == inout)
		param->attr = TEE_PARAM_ATTR_TYPE_MEMREF_INOUT;
	else if (flags & TEEC_MEM_INPUT)
		param->attr = TEE_PARAM_ATTR_TYPE_MEMREF_INPUT;
	else if (flags & TEEC_MEM_OUTPUT)
		param->attr = TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
	else
		return TEEC_ERROR_BAD_PARAMETERS;

	shm = memref->parent;
	/*
	 * We're using a shadow buffer in this reference, copy the real buffer
	 * into the shadow buffer if needed. We'll copy it back once we've
	 * returned from the call to secure world.
	 */
	if (shm->shadow_buffer && (flags & TEEC_MEM_INPUT))
		memcpy(shm->shadow_buffer, shm->buffer, shm->size);

	MEMREF_SHM_ID(param) = shm->id;
	MEMREF_SIZE(param) = shm->size;

	return TEEC_SUCCESS;
}

static TEEC_Result teec_pre_process_partial(uint32_t param_type,
		TEEC_RegisteredMemoryReference *memref,
		struct tee_param *param)
{
	uint32_t req_shm_flags = 0;
	TEEC_SharedMemory *shm = NULL;

	switch (param_type) {
	case TEEC_MEMREF_PARTIAL_INPUT:
		req_shm_flags = TEEC_MEM_INPUT;
		param->attr = TEE_PARAM_ATTR_TYPE_MEMREF_INPUT;
		break;
	case TEEC_MEMREF_PARTIAL_OUTPUT:
		req_shm_flags = TEEC_MEM_OUTPUT;
		param->attr = TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT;
		break;
	case TEEC_MEMREF_PARTIAL_INOUT:
		req_shm_flags = TEEC_MEM_OUTPUT | TEEC_MEM_INPUT;
		param->attr = TEE_PARAM_ATTR_TYPE_MEMREF_INOUT;
		break;
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	shm = memref->parent;

	if ((shm->flags & req_shm_flags) != req_shm_flags)
		return TEEC_ERROR_BAD_PARAMETERS;

	if ((memref->offset + memref->size < memref->offset) ||
	    (memref->offset + memref->size > shm->size))
		return TEEC_ERROR_BAD_PARAMETERS;

	/*
	 * We're using a shadow buffer in this reference, copy the real buffer
	 * into the shadow buffer if needed. We'll copy it back once we've
	 * returned from the call to secure world.
	 */
	if (shm->shadow_buffer && param_type != TEEC_MEMREF_PARTIAL_OUTPUT)
		memcpy((char *)shm->shadow_buffer + memref->offset,
		       (char *)shm->buffer + memref->offset, memref->size);

	MEMREF_SHM_ID(param) = shm->id;
	MEMREF_SHM_OFFS(param) = memref->offset;
	MEMREF_SIZE(param) = memref->size;

	return TEEC_SUCCESS;
}

static TEEC_Result teec_pre_process_operation(TEEC_Context *ctx,
		TEEC_Operation *operation,
		struct tee_param *params,
		TEEC_SharedMemory *shms)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	size_t n = 0;

	memset(shms, 0, sizeof(TEEC_SharedMemory) *
			TEEC_CONFIG_PAYLOAD_REF_COUNT);

	for (n = 0; n < TEEC_CONFIG_PAYLOAD_REF_COUNT; n++)
		shms[n].id = -1;

	if (!operation) {
		memset(params, 0, sizeof(struct tee_param) *
				TEEC_CONFIG_PAYLOAD_REF_COUNT);
		return TEEC_SUCCESS;
	}

	for (n = 0; n < TEEC_CONFIG_PAYLOAD_REF_COUNT; n++) {
		uint32_t param_type = 0;

		param_type = TEEC_PARAM_TYPE_GET(operation->paramTypes, n);
		switch (param_type) {
			case TEEC_NONE:
				params[n].attr = param_type;
				break;
			case TEEC_VALUE_INPUT:
			case TEEC_VALUE_OUTPUT:
			case TEEC_VALUE_INOUT:
				params[n].attr = param_type;
				params[n].a = operation->params[n].value.a;
				params[n].b = operation->params[n].value.b;
				break;
			case TEEC_MEMREF_TEMP_INPUT:
			case TEEC_MEMREF_TEMP_OUTPUT:
			case TEEC_MEMREF_TEMP_INOUT:
				res = teec_pre_process_tmpref(ctx, param_type,
						&operation->params[n].tmpref, params + n,
						shms + n);
				if (res != TEEC_SUCCESS)
					return res;
				break;
			case TEEC_MEMREF_WHOLE:
				res = teec_pre_process_whole(&operation->params[n].memref,
							     params + n);
				if (res != TEEC_SUCCESS) {
					return res;
				}
				break;
			case TEEC_MEMREF_PARTIAL_INPUT:
			case TEEC_MEMREF_PARTIAL_OUTPUT:
			case TEEC_MEMREF_PARTIAL_INOUT:
				res = teec_pre_process_partial(param_type,
						&operation->params[n].memref, params + n);
				if (res != TEEC_SUCCESS)
					return res;
				break;
			default:
				return TEEC_ERROR_BAD_PARAMETERS;
		}
	}

	return TEEC_SUCCESS;
}

static void teec_post_process_tmpref(uint32_t param_type,
		TEEC_TempMemoryReference *tmpref,
		struct tee_param *param,
		TEEC_SharedMemory *shm)
{
	if (param_type != TEEC_MEMREF_TEMP_INPUT) {
		if (tmpref->buffer && shm->shadow_buffer)
			memcpy(tmpref->buffer, shm->shadow_buffer,
					MIN(MEMREF_SIZE(param), tmpref->size));

		tmpref->size = MEMREF_SIZE(param);
	}
}

static void teec_post_process_whole(TEEC_RegisteredMemoryReference *memref,
				    struct tee_param *param)
{
	TEEC_SharedMemory *shm = memref->parent;

	if (shm->flags & TEEC_MEM_OUTPUT) {

		/*
		 * We're using a shadow buffer in this reference, copy back
		 * the shadow buffer into the real buffer now that we've
		 * returned from secure world.
		 */
		if (shm->shadow_buffer && MEMREF_SIZE(param) <= shm->size)
			memcpy(shm->buffer, shm->shadow_buffer, MEMREF_SIZE(param));

		memref->size = MEMREF_SIZE(param);
	}
}

static void teec_post_process_partial(uint32_t param_type, TEEC_RegisteredMemoryReference *memref,
				      struct tee_param *param)
{
	if (param_type != TEEC_MEMREF_PARTIAL_INPUT) {
		TEEC_SharedMemory *shm = memref->parent;

		/*
		 * We're using a shadow buffer in this reference, copy back
		 * the shadow buffer into the real buffer now that we've
		 * returned from secure world.
		 */
		if (shm->shadow_buffer && MEMREF_SIZE(param) <= memref->size)
			memcpy((char *)shm->buffer + memref->offset,
			       (char *)shm->shadow_buffer + memref->offset, MEMREF_SIZE(param));

		memref->size = MEMREF_SIZE(param);
	}
}

static void teec_post_process_operation(TEEC_Operation *operation, struct tee_param *params,
					TEEC_SharedMemory *shms)
{
	size_t n = 0;

	if (!operation)
		return;

	for (n = 0; n < TEEC_CONFIG_PAYLOAD_REF_COUNT; n++) {
		uint32_t param_type = 0;

		param_type = TEEC_PARAM_TYPE_GET(operation->paramTypes, n);
		switch (param_type) {
			case TEEC_VALUE_INPUT:
				break;
			case TEEC_VALUE_OUTPUT:
			case TEEC_VALUE_INOUT:
				operation->params[n].value.a = params[n].a;
				operation->params[n].value.b = params[n].b;
				break;
			case TEEC_MEMREF_TEMP_INPUT:
			case TEEC_MEMREF_TEMP_OUTPUT:
			case TEEC_MEMREF_TEMP_INOUT:
				teec_post_process_tmpref(param_type, &operation->params[n].tmpref,
							 params + n, shms + n);
				break;
			case TEEC_MEMREF_WHOLE:
				teec_post_process_whole(&operation->params[n].memref, params + n);
				break;
			case TEEC_MEMREF_PARTIAL_INPUT:
			case TEEC_MEMREF_PARTIAL_OUTPUT:
			case TEEC_MEMREF_PARTIAL_INOUT:
				teec_post_process_partial(param_type,
						&operation->params[n].memref, params + n);
			default:
				break;
		}
	}
}

static void teec_free_temp_refs(TEEC_Operation *operation, TEEC_SharedMemory *shms)
{
	size_t n = 0;

	if (!operation)
		return;

	for (n = 0; n < TEEC_CONFIG_PAYLOAD_REF_COUNT; n++) {
		switch (TEEC_PARAM_TYPE_GET(operation->paramTypes, n)) {
			case TEEC_MEMREF_TEMP_INPUT:
			case TEEC_MEMREF_TEMP_OUTPUT:
			case TEEC_MEMREF_TEMP_INOUT:
				TEEC_ReleaseSharedMemory(shms + n);
				break;
			default:
				break;
		}
	}
}

static TEEC_Result errno_to_res(int err)
{
	switch (err) {
		case ENOMEM:
			return TEEC_ERROR_OUT_OF_MEMORY;
		case EINVAL:
			return TEEC_ERROR_BAD_PARAMETERS;
		default:
			return TEEC_ERROR_GENERIC;
	}
}

static void uuid_to_octets(uint8_t d[TEE_UUID_LEN], const TEEC_UUID *s)
{
	d[0] = s->timeLow >> 24;
	d[1] = s->timeLow >> 16;
	d[2] = s->timeLow >> 8;
	d[3] = s->timeLow;
	d[4] = s->timeMid >> 8;
	d[5] = s->timeMid;
	d[6] = s->timeHiAndVersion >> 8;
	d[7] = s->timeHiAndVersion;
	memcpy(d + 8, s->clockSeqAndNode, sizeof(s->clockSeqAndNode));
}

static void setup_client_data(struct tee_open_session_arg *arg, uint32_t connection_method,
			      const void *connection_data)
{
	arg->clnt_login = connection_method;

	switch (connection_method) {
		case TEE_LOGIN_PUBLIC:
			/* No connection data to pass */
			break;
		case TEE_LOGIN_USER:
			/* Kernel auto-fills UID and forms client UUID */
			break;
		case TEE_LOGIN_GROUP:
			/*
			 * Connection data for group login is uint32_t and rest of
			 * clnt_uuid is set as zero.
			 *
			 * Kernel verifies group membership and then forms client UUID.
			 */
			memcpy(arg->clnt_uuid, connection_data, sizeof(gid_t));
			break;
		case TEE_LOGIN_APPLICATION:
			/*
			 * Kernel auto-fills application identifier and forms client
			 * UUID.
			 */
			break;
		case TEE_LOGIN_USER_APPLICATION:
			/*
			 * Kernel auto-fills application identifier, UID and forms
			 * client UUID.
			 */
			break;
		case TEE_LOGIN_GROUP_APPLICATION:
			/*
			 * Connection data for group login is uint32_t rest of
			 * clnt_uuid is set as zero.
			 *
			 * Kernel verifies group membership, auto-fills application
			 * identifier and then forms client UUID.
			 */
			memcpy(arg->clnt_uuid, connection_data, sizeof(gid_t));
			break;
		default:
			/*
			 * Unknown login method, don't pass any connection data as we
			 * don't know size.
			 */
			break;
	}
}

TEEC_Result TEEC_OpenSession(TEEC_Context *ctx, TEEC_Session *session,
		const TEEC_UUID *destination,
		uint32_t connection_method, const void *connection_data,
		TEEC_Operation *operation, uint32_t *ret_origin)
{
	struct tee_open_session_arg arg;
	struct tee_param params[TEEC_CONFIG_PAYLOAD_REF_COUNT];
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t eorig = 0;
	int rc = 0;
	const size_t arg_size = sizeof(struct tee_open_session_arg) +
		TEEC_CONFIG_PAYLOAD_REF_COUNT *
		sizeof(struct tee_param);
	uint32_t session_id;
	union {
		struct tee_open_session_arg arg;
		uint8_t data[arg_size];
	} buf;
	TEEC_SharedMemory shm[TEEC_CONFIG_PAYLOAD_REF_COUNT];

	memset(&buf, 0, sizeof(buf));
	memset(&shm, 0, sizeof(shm));

	if (!ctx || !session) {
		eorig = TEEC_ORIGIN_API;
		res = TEEC_ERROR_BAD_PARAMETERS;
		goto out;
	}

	uuid_to_octets(arg.uuid, destination);

	setup_client_data(&arg, connection_method, connection_data);

	res = teec_pre_process_operation(ctx, operation, params, shm);
	if (res != TEEC_SUCCESS) {
		eorig = TEEC_ORIGIN_API;
		goto out_free_temp_refs;
	}

	rc = tee_open_session(ctx->dev, &arg, TEEC_CONFIG_PAYLOAD_REF_COUNT, params, &session_id);
	if (rc) {
		LOG_ERR("tee_open_session failed");
		eorig = TEEC_ORIGIN_COMMS;
		res = errno_to_res(errno);
		goto out_free_temp_refs;
	}
	res = arg.ret;
	eorig = arg.ret_origin;
	if (res == TEEC_SUCCESS) {
		session->ctx = ctx;
		session->session_id = session_id;
	}
	teec_post_process_operation(operation, params, shm);

out_free_temp_refs:
	teec_free_temp_refs(operation, shm);
out:
	if (ret_origin)
		*ret_origin = eorig;
	return res;
}

void TEEC_CloseSession(TEEC_Session *session)
{
	if (!session || !session->ctx)
		return;

	if (tee_close_session(session->ctx->dev, session->session_id))
		LOG_ERR("Failed to close session 0x%x", session->session_id);
}

TEEC_Result TEEC_InvokeCommand(TEEC_Session *session, uint32_t cmd_id,
			       TEEC_Operation *operation, uint32_t *error_origin)
{
	struct tee_invoke_func_arg arg;
	struct tee_param params[TEEC_CONFIG_PAYLOAD_REF_COUNT];
	TEEC_Result res = TEEC_ERROR_GENERIC;
	uint32_t eorig = 0;
	int rc = 0;
	TEEC_SharedMemory shm[TEEC_CONFIG_PAYLOAD_REF_COUNT];

	memset(&shm, 0, sizeof(shm));
	memset(params, 0, sizeof(params));

	if (!session) {
		eorig = TEEC_ORIGIN_API;
		res = TEEC_ERROR_BAD_PARAMETERS;
		goto out;
	}

	arg.session = session->session_id;
	arg.func = cmd_id;

	if (operation) {
		teec_mutex_lock(&teec_mutex);
		operation->session = session;
		teec_mutex_unlock(&teec_mutex);
	}

	res = teec_pre_process_operation(session->ctx, operation, params, shm);
	if (res != TEEC_SUCCESS) {
		eorig = TEEC_ORIGIN_API;
		goto out_free_temp_refs;
	}
	rc = tee_invoke_func(session->ctx->dev, &arg, TEEC_CONFIG_PAYLOAD_REF_COUNT, params);
	if (rc) {
		LOG_ERR("tee_invoke_func failed");
		eorig = TEEC_ORIGIN_COMMS;
		res = errno_to_res(errno);
		goto out_free_temp_refs;
	}

	res = arg.ret;
	eorig = arg.ret_origin;
	teec_post_process_operation(operation, params, shm);

out_free_temp_refs:
	teec_free_temp_refs(operation, shm);
out:
	if (error_origin)
		*error_origin = eorig;
	return res;
}

void TEEC_RequestCancellation(TEEC_Operation *operation)
{
	TEEC_Session *session = NULL;

	if (!operation)
		return;

	teec_mutex_lock(&teec_mutex);
	session = operation->session;
	teec_mutex_unlock(&teec_mutex);

	if (!session)
		return;

	if (tee_cancel(session->ctx->dev, session->session_id, 0))
		LOG_ERR("TEE_IOC_CANCEL: %s", strerror(errno));
}

TEEC_Result TEEC_RegisterSharedMemory(TEEC_Context *ctx, TEEC_SharedMemory *shm)
{
	TEEC_Result res = TEEC_SUCCESS;
	size_t s = 0;
	struct tee_shm *shmem;
	int ret;

	if (!ctx || !shm)
		return TEEC_ERROR_BAD_PARAMETERS;

	if (!shm->flags || (shm->flags & ~(TEEC_MEM_INPUT | TEEC_MEM_OUTPUT)))
		return TEEC_ERROR_BAD_PARAMETERS;

	if (!shm->buffer)
		return TEEC_ERROR_BAD_PARAMETERS;

	s = shm->size;
	if (!s)
		s = 8;

	shm->dev = ctx->dev;
	if (ctx->reg_mem) {
		ret = teec_shm_register(ctx->dev, shm->buffer, s, shm->flags, &shmem);
		if (ret == 0) {
			shm->registered_shm = shmem;
			shm->id = (unsigned long)shmem;
			shm->shadow_buffer = NULL;
			shm->internal.flags = 0;
			goto out;
		}

		/*
		 * If we're here teec_shm_register failed, probably
		 * because some read-only memory was supplied and the Zephyr
		 * kernel doesn't like that at the moment.
		 *
		 * The error could also have some other origin. In any case
		 * we're not making matters worse by trying to allocate and
		 * register a shadow buffer before giving up.
		 */
		shm->shadow_buffer = teec_paged_aligned_alloc(s);
		if (!shm->shadow_buffer)
			return TEEC_ERROR_OUT_OF_MEMORY;
		ret = teec_shm_register(ctx->dev, shm->shadow_buffer, s, shm->flags, &shmem);
		if (ret == 0) {
			shm->registered_shm = shmem;
			shm->id = (unsigned long)shmem;
			shm->internal.flags = SHM_FLAG_SHADOW_BUFFER_ALLOCED;
			goto out;
		}

		if (errno == ENOMEM)
			res = TEEC_ERROR_OUT_OF_MEMORY;
		else
			res = TEEC_ERROR_GENERIC;
		k_free(shm->shadow_buffer);
		shm->shadow_buffer = NULL;
		return res;
	} else {
		shm->shadow_buffer = teec_shm_alloc(ctx->dev, s, 0);
		if (!shm->shadow_buffer)
			return TEEC_ERROR_OUT_OF_MEMORY;

		shm->registered_shm = NULL;
		shm->internal.flags = 0;
	}

out:
	shm->alloced_size = s;
	return TEEC_SUCCESS;
}

TEEC_Result TEEC_AllocateSharedMemory(TEEC_Context *ctx, TEEC_SharedMemory *shm)
{
	size_t s = 0;
	int ret;

	if (!ctx || !shm)
		return TEEC_ERROR_BAD_PARAMETERS;

	if (!shm->flags || (shm->flags & ~(TEEC_MEM_INPUT | TEEC_MEM_OUTPUT)))
		return TEEC_ERROR_BAD_PARAMETERS;

	s = shm->size;
	if (!s)
		s = 8;

	shm->dev = ctx->dev;
	if (ctx->reg_mem) {
		struct tee_shm *shmem;

		shm->buffer = teec_paged_aligned_alloc(s);
		if (!shm->buffer)
			return TEEC_ERROR_OUT_OF_MEMORY;

		ret = teec_shm_register(ctx->dev, shm->buffer, s, 0, &shmem);
		if (ret) {
			k_free(shm->buffer);
			shm->buffer = NULL;
			return TEEC_ERROR_OUT_OF_MEMORY;
		}
		shm->registered_shm = shmem;
		shm->id = (unsigned long)shmem;
	} else {
		shm->buffer = teec_shm_alloc(ctx->dev, s, 0);

		if (!shm->buffer) {
			shm->id = -1;
			return TEEC_ERROR_OUT_OF_MEMORY;
		}
		shm->registered_shm = NULL;
	}

	shm->shadow_buffer = NULL;
	shm->alloced_size = s;
	shm->internal.flags = SHM_FLAG_BUFFER_ALLOCED;
	return TEEC_SUCCESS;
}

void TEEC_ReleaseSharedMemory(TEEC_SharedMemory *shm)
{
	if (!shm || shm->id == -1 || !shm->dev)
		return;

	if (shm->shadow_buffer) {
		if (shm->registered_shm) {
			if (shm->internal.flags & SHM_FLAG_SHADOW_BUFFER_ALLOCED)
				k_free(shm->shadow_buffer);
			tee_shm_unregister(shm->dev, shm->registered_shm);
		}
	} else if (shm->buffer) {
		if (shm->registered_shm) {
			if (shm->internal.flags & SHM_FLAG_BUFFER_ALLOCED)
				k_free(shm->buffer);
			tee_shm_unregister(shm->dev, shm->registered_shm);
		}
	} else if (shm->registered_shm) {
		tee_shm_unregister(shm->dev, shm->registered_shm);
	}

	shm->id = -1;
	shm->shadow_buffer = NULL;
	shm->buffer = NULL;
	shm->registered_shm = NULL;
	shm->internal.flags = 0;
}
