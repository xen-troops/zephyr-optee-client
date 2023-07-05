// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2023 EPAM Systems
 *
 */


#include <optee_msg_supplicant.h>
#include <ree_fs.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/fdtable.h>

LOG_MODULE_REGISTER(ree_fs);

/* where FS gets mounted */
/*TODO: make it in sync with DTS fstab */
#define REE_FS_MP "/tee"
#define REE_FS_PATHLEN sizeof(REE_FS_MP)
#define REE_FS_PATH_MAX (PATH_MAX + REE_FS_PATHLEN)

static int tee_fs_open(size_t num_params, struct tee_param *params,
		       fs_mode_t flags)
{
	struct tee_shm *shm;
	char *name, path[REE_FS_PATH_MAX] = REE_FS_MP;
	struct fs_file_t *file;
	int fd, rc = TEEC_ERROR_GENERIC;

	if (num_params != 3) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_INPUT ||
	    (params[2].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/*TODO do all safety checks */
	shm = (struct tee_shm *)params[1].c;

	if (!shm || !shm->addr) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	name = shm->addr;
	strncat(path, name, PATH_MAX);

	file = k_malloc(sizeof(*file));
	if (!file) {
		return TEEC_ERROR_GENERIC;
	}

	fs_file_t_init(file);
	fd = z_alloc_fd(file, NULL);
	if (fd < 0) {
		rc = TEEC_ERROR_GENERIC;
		goto free;
	}

	rc = fs_open(file, path, flags);
	if (rc < 0) {
		if (rc == -ENOENT) {
			rc = TEEC_ERROR_ITEM_NOT_FOUND;
			goto free;
		}
		LOG_ERR("failed to open/create %s (%d)", path, rc);
		rc = TEEC_ERROR_GENERIC;
		goto free;
	}

	params[2].a = fd;

	return TEEC_SUCCESS;
free:
	if (fd >= 0) {
		z_free_fd(fd);
	}
	k_free(file);
	return rc;
}

static int tee_fs_close(size_t num_params, struct tee_param *params)
{
	int fd, rc;
	struct fs_file_t *file;

	if (num_params != 1 || (params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	fd = params[0].b;

	file = z_get_fd_obj(fd, NULL, 0);
	if (!file) {
		LOG_ERR("fd %d not found", fd);
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	rc = fs_close(file);
	z_free_fd(fd);
	k_free(file);

	if (rc < 0) {
		LOG_ERR("failed to close file (%d)", rc);
		return TEEC_ERROR_GENERIC;
	}

	return TEEC_SUCCESS;
}

static int tee_fs_read(size_t num_params, struct tee_param *params)
{
	int fd, rc;
	off_t offset;
	size_t len;
	ssize_t sz;
	struct tee_shm *shm;
	struct fs_file_t *file;
	void *buf;

	if (num_params != 2) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	fd = params[0].b;
	offset = params[0].c;

	file = z_get_fd_obj(fd, NULL, 0);
	if (!file) {
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	/*TODO do all safety checks */
	shm = (struct tee_shm *)params[1].c;
	len = params[1].b;

	if (!shm || !shm->addr) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	buf = shm->addr;
	rc = fs_seek(file, offset, SEEK_SET);
	if (rc < 0) {
		LOG_ERR("invalid offset %ld (%d)", offset, rc);
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	/*TODO: handle sz < len */
	sz = fs_read(file, buf, len);
	if (sz < 0) {
		LOG_ERR("read failure (%ld)", sz);
		return TEEC_ERROR_GENERIC;
	}

	params[1].b = sz;
	return TEEC_SUCCESS;
}

static int tee_fs_write(size_t num_params, struct tee_param *params)
{
	int fd, rc;
	off_t offset;
	size_t len;
	ssize_t sz;
	struct tee_shm *shm;
	struct fs_file_t *file;
	void *buf;

	if (num_params != 2) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_INPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	fd = params[0].b;
	offset = params[0].c;

	file = z_get_fd_obj(fd, NULL, 0);
	if (!file) {
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	/*TODO do all safety checks */
	shm = (struct tee_shm *)params[1].c;
	len = params[1].b;

	if (!shm || !shm->addr) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	buf = shm->addr;
	rc = fs_seek(file, offset, SEEK_SET);
	if (rc < 0) {
		LOG_ERR("invalid offset %ld (%d)", offset, rc);
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	/*TODO: handle case of partially written buffer */
	sz = fs_write(file, buf, len);
	if (sz < 0) {
		LOG_ERR("write failure (%ld)", sz);
		return TEEC_ERROR_GENERIC;
	}

	params[1].b = sz;
	return TEEC_SUCCESS;
}

static int tee_fs_truncate(size_t num_params, struct tee_param *params)
{
	int rc, fd;
	off_t len;
	struct fs_file_t *file;

	if (num_params != 1 || (params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	fd = params[0].b;
	len = params[0].c;

	file = z_get_fd_obj(fd, NULL, 0);
	if (!file) {
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	rc = fs_truncate(file, len);
	if (rc < 0) {
		LOG_ERR("failed to truncate (%d)", rc);
		return TEEC_ERROR_GENERIC;
	}

	return TEEC_SUCCESS;
}

static int tee_fs_remove(size_t num_params, struct tee_param *params)
{
	struct tee_shm *shm;
	char *name, path[REE_FS_PATH_MAX] = REE_FS_MP;
	int rc;

	if (num_params != 2) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_INPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/*TODO do all safety checks */
	shm = (struct tee_shm *)params[1].c;

	if (!shm || !shm->addr) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	name = shm->addr;
	strncat(path, name, PATH_MAX);

	rc = fs_unlink(path);
	if (rc < 0) {
		if (rc == -ENOENT) {
			return TEEC_ERROR_ITEM_NOT_FOUND;
		}
		LOG_ERR("failed to unlink %s (%d)", path, rc);
		return TEEC_ERROR_GENERIC;
	}

	/*TODO: cleanup empty directories */
	return TEEC_SUCCESS;
}

static int tee_fs_rename(size_t num_params, struct tee_param *params)
{
	char *name, path[REE_FS_PATH_MAX] = REE_FS_MP;
	char *new_name, new_path[REE_FS_PATH_MAX] = REE_FS_MP;
	struct tee_shm *shm;
	int rc;

	if (num_params != 3) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_INPUT ||
	    (params[2].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_INPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/*TODO do all safety checks */
	shm = (struct tee_shm *)params[1].c;

	if (!shm || !shm->addr) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	name = shm->addr;
	strncat(path, name, PATH_MAX);

	shm = (struct tee_shm *)params[2].c;

	if (!shm || !shm->addr) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	new_name = shm->addr;
	strncat(new_path, new_name, PATH_MAX);

	/* overwrite flag */
	if (!params[0].b) {
		struct fs_statvfs buf;

		if (!fs_statvfs(new_path, &buf)) {
			return TEEC_ERROR_ACCESS_CONFLICT;
		}
	}

	rc = fs_rename(path, new_path);
	if (rc < 0) {
		LOG_ERR("failed to rename %s -> %s (%d)",
			path, new_path, rc);
		return TEEC_ERROR_GENERIC;
	}

	return TEEC_SUCCESS;
}

static int tee_fs_opendir(size_t num_params, struct tee_param *params)
{
	struct tee_shm *shm;
	char *name, path[REE_FS_PATH_MAX] = REE_FS_MP;
	struct fs_dir_t *dir;
	int rc;

	if (num_params != 3) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_INPUT ||
	    (params[2].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/*TODO do all safety checks */
	shm = (struct tee_shm *)params[1].c;

	if (!shm || !shm->addr) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	name = shm->addr;
	strncat(path, name, PATH_MAX);

	dir = k_malloc(sizeof(*dir));
	if (!dir) {
		return TEEC_ERROR_GENERIC;
	}

	fs_dir_t_init(dir);
	rc = fs_opendir(dir, path);
	if (rc < 0) {
		LOG_ERR("failed to open %s (%d)", path, rc);
		k_free(dir);
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	params[2].a = (uint64_t)dir;

	return TEEC_SUCCESS;
}

static int tee_fs_closedir(size_t num_params, struct tee_param *params)
{
	struct fs_dir_t *dir;
	int rc;

	if (num_params != 1 || (params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/*TODO do all safety checks */
	dir = (struct fs_dir_t *)params[0].b;
	if (!dir) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	rc = fs_closedir(dir);
	k_free(dir);

	if (rc < 0) {
		LOG_ERR("closedir failed (%d)", rc);
		return TEEC_ERROR_GENERIC;
	}

	return TEEC_SUCCESS;
}

static int tee_fs_readdir(size_t num_params, struct tee_param *params)
{
	struct tee_shm *shm;
	struct fs_dirent entry;
	struct fs_dir_t *dir;
	size_t len;
	int rc;

	if (num_params != 2) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	/*TODO do all safety checks */
	dir = (struct fs_dir_t *)params[0].b;
	shm = (struct tee_shm *)params[1].c;

	if (!dir || !shm || !shm->addr) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if (params[1].b != shm->size) {
		LOG_WRN("memref size not match shm size");
	}

	rc = fs_readdir(dir, &entry);
	if (rc < 0) {
		LOG_ERR("readdir failure (%d)", rc);
		return TEEC_ERROR_GENERIC;
	}

	if (entry.name[0] == 0) {
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	len = strlen(entry.name) + 1;
	if (shm->size < len) {
		return TEEC_ERROR_SHORT_BUFFER;
	}

	memcpy(shm->addr, entry.name, len);
	return TEEC_SUCCESS;
}

int tee_fs(uint32_t num_params, struct tee_param *params)
{
	unsigned int mrf = -1;

	switch (params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) {
	case TEE_PARAM_ATTR_TYPE_VALUE_INPUT:
	case TEE_PARAM_ATTR_TYPE_VALUE_OUTPUT:
	case TEE_PARAM_ATTR_TYPE_VALUE_INOUT:
		mrf = params[0].a;
		break;
	default:
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	switch (mrf) {
	case OPTEE_MRF_OPEN:
		return tee_fs_open(num_params, params, FS_O_RDWR);
	case OPTEE_MRF_CREATE:
		return tee_fs_open(num_params, params, FS_O_RDWR | FS_O_CREATE);
	case OPTEE_MRF_CLOSE:
		return tee_fs_close(num_params, params);
	case OPTEE_MRF_READ:
		return tee_fs_read(num_params, params);
	case OPTEE_MRF_WRITE:
		return tee_fs_write(num_params, params);
	case OPTEE_MRF_TRUNCATE:
		return tee_fs_truncate(num_params, params);
	case OPTEE_MRF_REMOVE:
		return tee_fs_remove(num_params, params);
	case OPTEE_MRF_RENAME:
		return tee_fs_rename(num_params, params);
	case OPTEE_MRF_OPENDIR:
		return tee_fs_opendir(num_params, params);
	case OPTEE_MRF_CLOSEDIR:
		return tee_fs_closedir(num_params, params);
	case OPTEE_MRF_READDIR:
		return tee_fs_readdir(num_params, params);
	};

	return TEEC_ERROR_BAD_PARAMETERS;
}


