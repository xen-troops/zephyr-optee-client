/*
 * Copyright (c) 2024 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/drivers/tee.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/dlist.h>
#include <zephyr/fs/fs.h>

#include <optee_msg_supplicant.h>
#include <tee_client_api.h>
#include <teec_ta_load.h>
#include <ree_fs.h>
#include "tee_supplicant.h"

LOG_MODULE_REGISTER(tee_supplicant);

#define TEE_SUPP_THREAD_PRIO	7

#define TEE_REQ_PARAM_MAX	5

#define MEM_ID(id) ((id) ? (uint64_t)((struct tee_shm *)(id))->addr : 0)
static struct k_thread main_thread;
static K_THREAD_STACK_DEFINE(main_stack, 8192);

static sys_dlist_t shm_list;
static K_MUTEX_DEFINE(shm_mutex);

struct tee_supp_msg {
	uint32_t cmd_ret;
	uint32_t num_param;
	struct tee_param params[TEE_REQ_PARAM_MAX];
};

struct param_value {
	uint64_t a;
	uint64_t b;
	uint64_t c;
};

struct suppl_shm {
	uint64_t id;
	void *p;
	size_t size;
	sys_dnode_t link;
};

static int receive_request(const struct device *dev, struct tee_supp_msg *ts_req)
{
	int rc = tee_suppl_recv(dev, &ts_req->cmd_ret, &ts_req->num_param, ts_req->params);

	if (rc) {
		LOG_ERR("TEE supplicant receive failed, rc = %d", rc);
	}

	return rc;
}

static struct suppl_shm *find_shm(uint64_t id)
{
	struct suppl_shm *node;
	uint64_t mem_id;

	if (!id) {
		return NULL;
	}
	mem_id = MEM_ID(id);

	k_mutex_lock(&shm_mutex, K_FOREVER);

	SYS_DLIST_FOR_EACH_CONTAINER(&shm_list, node, link) {
		if (node->id == mem_id) {
			break;
		}
	}

	k_mutex_unlock(&shm_mutex);
	return node;
}

static struct suppl_shm *remove_shm(uint64_t id)
{
	struct suppl_shm *node;
	uint64_t mem_id;

	if (!id) {
		return NULL;
	}
	mem_id = MEM_ID(id);

	k_mutex_lock(&shm_mutex, K_FOREVER);

	node = find_shm(id);
	if (node) {
		sys_dlist_remove(&node->link);
	}
	k_mutex_unlock(&shm_mutex);

	return node;
}

static void append_shm(struct suppl_shm *shm)
{
	k_mutex_lock(&shm_mutex, K_FOREVER);

	sys_dnode_init(&shm->link);
	sys_dlist_append(&shm_list, &shm->link);

	k_mutex_unlock(&shm_mutex);
}

void *tee_param_get_mem(struct tee_param *param, size_t *size)
{
	struct suppl_shm *shm = NULL;

	switch (param->attr & TEE_PARAM_ATTR_TYPE_MASK) {
	case TEE_PARAM_ATTR_TYPE_MEMREF_INPUT:
	case TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT:
	case TEE_PARAM_ATTR_TYPE_MEMREF_INOUT:
		break;
	default:
		return NULL;
	}

	shm = find_shm(MEMREF_SHM_ID(param));
	if (!shm) {
		return NULL;
	}

	if (size) {
		*size = shm->size;
	}
	return shm->p;
}

static int send_response(const struct device *dev, struct tee_supp_msg *rsp)
{
	int rc = tee_suppl_send(dev, rsp->cmd_ret, rsp->num_param, rsp->params);

	if (rc) {
		LOG_ERR("TEE supplicant send response failed, rc = %d", rc);
	}

	return rc;
}

static void uuid_from_param(TEEC_UUID *d, const uint64_t a, const uint64_t b)
{
	const uint8_t *sa = (const uint8_t *)&a;
	const uint8_t *sb = (const uint8_t *)&b;

	d->timeLow = (sa[0] << 24) | (sa[1] << 16) | (sa[2] << 8) | sa[3];
	d->timeMid = (sa[4] << 8) | sa[5];
	d->timeHiAndVersion = (sa[6] << 8) | sa[7];
	memcpy(d->clockSeqAndNode, sb, sizeof(d->clockSeqAndNode));
}

static int load_ta(uint32_t num_params, struct tee_param *params)
{
	int ta_found = 0;
	void *addr;
	size_t size = 0;
	size_t buf_size = 0;
	TEEC_UUID uuid = { 0 };

	if (num_params != 2) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) != TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) != TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	uuid_from_param(&uuid, params[0].a, params[0].b);

	addr = tee_param_get_mem(params + 1, &buf_size);
	size = buf_size;

	ta_found = TEECI_LoadSecureModule(&uuid, addr, &size);
	if (ta_found != TA_BINARY_FOUND) {
		LOG_ERR("TA not found");
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	SET_MEMREF_SIZE(params + 1, size);

	/*
	 * If a buffer wasn't provided, just tell which size it should be.
	 * If it was provided but isn't big enough, report an error.
	 */
	if (addr && size > buf_size) {
		return TEEC_ERROR_SHORT_BUFFER;
	}

	return TEEC_SUCCESS;
}

static int shm_alloc(const struct device *dev, uint32_t num_params,
		     struct tee_param *params)
{
	void *addr;
	size_t size;
	struct suppl_shm *shm;

	if (num_params != 1) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	switch (params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) {
	case TEE_PARAM_ATTR_TYPE_VALUE_INPUT:
	case TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT:
	case TEE_PARAM_ATTR_TYPE_VALUE_INOUT:
		size = MEMREF_SIZE(params);
		break;
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/*TODO: page-aligned allocation may not be required here, also we'd
	 * better double check what alignment optee wants
	 */
	addr = k_aligned_alloc(CONFIG_MMU_PAGE_SIZE, size);
	if (!addr) {
		return TEEC_ERROR_OUT_OF_MEMORY;
	}

	shm = k_malloc(sizeof(struct suppl_shm));
	if (!shm) {
		k_free(addr);
		return TEEC_ERROR_OUT_OF_MEMORY;
	}
	shm->p = addr;
	shm->id = (uint64_t)addr;
	shm->size = size;
	append_shm(shm);

	SET_MEMREF_SHM_ID(params, shm->id);
	return TEEC_SUCCESS;
}

static int shm_free(uint32_t num_params, struct tee_param *params)
{
	uint64_t id;
	struct suppl_shm *shm = NULL;

	if (num_params != 1) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	switch (params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) {
	case TEE_PARAM_ATTR_TYPE_VALUE_INPUT:
	case TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT:
	case TEE_PARAM_ATTR_TYPE_VALUE_INOUT:
		id = params[0].b;
		break;
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	shm = remove_shm(id);
	if (!shm) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	k_free(shm->p);
	k_free(shm);
	return TEEC_SUCCESS;
}

static int process_request(const struct device *dev)
{
	int rc;
	struct tee_supp_msg ts_msg = {
		.num_param = TEE_REQ_PARAM_MAX,
	};

	rc = receive_request(dev, &ts_msg);
	if (rc) {
		return rc;
	}

	LOG_DBG("Receive OPTEE request cmd #%d", ts_msg.cmd_ret);
	switch (ts_msg.cmd_ret) {
	case OPTEE_MSG_RPC_CMD_LOAD_TA:
		rc = load_ta(ts_msg.num_param, ts_msg.params);
		break;
	case OPTEE_MSG_RPC_CMD_FS:
		rc = tee_fs(ts_msg.num_param, ts_msg.params);
		break;
	case OPTEE_MSG_RPC_CMD_SHM_ALLOC:
		rc = shm_alloc(dev, ts_msg.num_param, ts_msg.params);
		break;
	case OPTEE_MSG_RPC_CMD_SHM_FREE:
		rc = shm_free(ts_msg.num_param, ts_msg.params);
		break;
	default:
		return TEEC_ERROR_NOT_SUPPORTED;
	}

	ts_msg.cmd_ret = rc;
	return send_response(dev, &ts_msg);
}

static void tee_supp_main(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);
	const struct device *dev = p1;
	int rc = 0;

	/* TODO: implement terminating supplicant's thread */
	while (1) {
		rc = process_request(dev);
		if (rc) {
			LOG_ERR("Failed to process request, rc = %d", rc);
		}
	}
}

static char *_strdup(const char *str)
{
	int len;
	char *s;

	len = strlen(str) + 1;
	s = k_malloc(len);
	if (s) {
		strcpy(s, str);
	}
	return s;
}

static int do_mkdir(const char *path)
{
	int rc;

	rc = fs_mkdir(path);
	if (rc == -EEXIST) {
		rc = 0;
	}

	return rc;
}

static int mkpath(const char *path)
{
	int status = 0;
	char *subpath = _strdup(path);
	char *prev = subpath;
	char *curr = NULL;

	if (!subpath) {
		return -ENOMEM;
	}
	while (status == 0 && (curr = strchr(prev, '/')) != 0) {
		if (curr != prev) {
			*curr = '\0';
			status = do_mkdir(subpath);
			*curr = '/';
		}
		prev = curr + 1;
	}
	if (status == 0) {
		status = do_mkdir(path);
	}
	k_free(subpath);
	return status;
}

static int tee_supp_init(const struct device *dev)
{
	const struct device *tee_dev = DEVICE_DT_GET_ONE(linaro_optee_tz);
	struct tee_version_info info = { 0 };
	int rc;

	if (!tee_dev) {
		LOG_ERR("No TrustZone device found!");
		return -ENODEV;
	}

	sys_dlist_init(&shm_list);

	if (tee_get_version(tee_dev, &info)) {
		LOG_ERR("Unable to retrieve tee capabilities");
		return -EINVAL;
	}
	if (!(info.gen_caps & TEE_GEN_CAP_REG_MEM)) {
		LOG_ERR("Only shared memory registration supported");
		return -EINVAL;
	}

	rc = mkpath(CONFIG_OPTEE_STORAGE_ROOT);
	if (rc != 0) {
		LOG_ERR("Prepare secure storage failed %d", rc);
		return rc;
	}

	k_thread_create(&main_thread, main_stack, K_THREAD_STACK_SIZEOF(main_stack), tee_supp_main,
			(void *) tee_dev, NULL, NULL, TEE_SUPP_THREAD_PRIO, 0, K_NO_WAIT);

	LOG_INF("Started tee_supplicant thread");
	return 0;
}

#ifdef CONFIG_OPTEE_TEE_SUPPLICANT_AUTOINIT
SYS_INIT(tee_supp_init, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
#else
int TEE_SupplicantInit(void)
{
	return tee_supp_init(NULL);
}
#endif
