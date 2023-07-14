/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/drivers/tee.h>
#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <optee_msg_supplicant.h>
#include <tee_client_api.h>
#include <teec_ta_load.h>

LOG_MODULE_REGISTER(tee_supplicant);

#define TEE_SUPP_THREAD_PRIO	7

#define TEE_REQ_PARAM_MAX	5

static struct k_thread main_thread;
static K_THREAD_STACK_DEFINE(main_stack, 8192);

static K_MUTEX_DEFINE(shm_mutex);

#define MEMREF_SHM_ID(p)	((p)->c)
#define MEMREF_SHM_OFFS(p)	((p)->a)
#define MEMREF_SIZE(p)		((p)->b)

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

static int receive_request(const struct device *dev, struct tee_supp_msg *ts_req)
{
	int rc = tee_suppl_recv(dev, &ts_req->cmd_ret, &ts_req->num_param, ts_req->params);

	if (rc) {
		LOG_ERR("TEE supplicant receive failed, rc = %d", rc);
	}

	return rc;
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
	size_t size = 0;
	TEEC_UUID uuid = { 0 };
	struct tee_shm *shm;
	void *addr;

	if (num_params != 2) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) != TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) != TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	shm = (struct tee_shm *)params[1].c;
	uuid_from_param(&uuid, params[0].a, params[0].b);

	if (shm) {
		size = shm->size;
		addr = shm->addr;
	} else {
		size = 0;
		addr = NULL;
	}

	ta_found = TEECI_LoadSecureModule(&uuid, addr, &size);
	if (ta_found != TA_BINARY_FOUND) {
		LOG_ERR("TA not found");
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	MEMREF_SIZE(params + 1) = size;

	/*
	 * If a buffer wasn't provided, just tell which size it should be.
	 * If it was provided but isn't big enough, report an error.
	 */
	if (addr && size > (shm ? shm->size : 0)) {
		return TEEC_ERROR_SHORT_BUFFER;
	}

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

	while (1) {
		rc = process_request(dev);
		if (rc) {
			LOG_ERR("Failed to process request, rc = %d", rc);
		}
	}
}

static int tee_supp_init(const struct device *dev)
{
	const struct device *tee_dev = DEVICE_DT_GET_ONE(linaro_optee_tz);

	if (!tee_dev) {
		LOG_ERR("No TrustZone device found!");
		return -ENODEV;
	}

	k_thread_create(&main_thread, main_stack, K_THREAD_STACK_SIZEOF(main_stack), tee_supp_main,
			(void *) tee_dev, NULL, NULL, TEE_SUPP_THREAD_PRIO, 0, K_NO_WAIT);

	LOG_INF("Started tee_supplicant thread");
	return 0;
}

SYS_INIT(tee_supp_init, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
