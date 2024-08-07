// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2024 EPAM Systems
 *
 */

#include <optee_msg_supplicant.h>
#include <ree_fs.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/logging/log.h>
#include <zephyr/sys/fdtable.h>
#include "tee_supplicant.h"

LOG_MODULE_REGISTER(ree_fs);

#define REE_FS_MP CONFIG_OPTEE_STORAGE_ROOT
#define REE_FS_PATHLEN sizeof(REE_FS_MP)
#define REE_FS_PATH_MAX (PATH_MAX + REE_FS_PATHLEN)

#define MAX_FILES		20

static struct fs_file_t *files[MAX_FILES] = {0};
K_MUTEX_DEFINE(file_mutex);

static struct fs_file_t *find_fd(int fd)
{
	struct fs_file_t *file;

	if (fd < 0 || fd >= MAX_FILES) {
		return NULL;
	}

	k_mutex_lock(&file_mutex, K_FOREVER);
	file = files[fd];
	k_mutex_unlock(&file_mutex);
	return file;
}

static void remove_fd(int fd)
{
	struct fs_file_t *file;

	if (fd < 0 || fd >= MAX_FILES) {
		return;
	}
	k_mutex_lock(&file_mutex, K_FOREVER);
	file = files[fd];
	if (file) {
		k_free(file);
	}
	files[fd] = NULL;
	k_mutex_unlock(&file_mutex);
}

static int new_fd(struct fs_file_t **file)
{
	int fd;

	if (!file) {
		return -EINVAL;
	}

	*file = k_malloc(sizeof(struct fs_file_t));
	if (!(*file)) {
		return -ENOMEM;
	}

	k_mutex_lock(&file_mutex, K_FOREVER);
	fs_file_t_init(*file);
	for (fd = 0; fd < MAX_FILES; fd++) {
		if (!files[fd]) {
			files[fd] = *file;
			k_mutex_unlock(&file_mutex);
			return fd;
		}
	}
	k_mutex_unlock(&file_mutex);
	k_free(*file);

	return -EMFILE;
}

static int tee_fs_open(size_t num_params, struct tee_param *params,
		       fs_mode_t flags)
{
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

	name = tee_param_get_mem(params + 1, NULL);
	if (!name) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	strncat(path, name, PATH_MAX);

	fd = new_fd(&file);
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
		remove_fd(fd);
	}
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

	file = find_fd(fd);
	if (!file) {
		LOG_ERR("fd %d not found", fd);
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	rc = fs_close(file);
	remove_fd(fd);

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
	ssize_t sz, s;
	struct fs_file_t *file;
	uint8_t *buf;

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

	file = find_fd(fd);
	if (!file) {
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	buf = tee_param_get_mem(params + 1, NULL);
	if (!buf) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	len = MEMREF_SIZE(params + 1);
	sz = 0;
	rc = fs_seek(file, offset, SEEK_SET);
	if (rc == -EINVAL) {
		/*
		 * OP-TEE tries to seek past the end of file. POSIX
		 * allows this, but Zephyr - does not. POSIX in such
		 * case just returns 0 for the read operation, we will
		 * do the same.
		 */
		SET_MEMREF_SIZE(params + 1, 0);
		return TEEC_SUCCESS;
	}
	if (rc < 0) {
		LOG_ERR("invalid offset %ld (%d)", offset, rc);
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}
	while (len > 0) {
		s = fs_read(file, buf, len);
		if (s < 0) {
			LOG_ERR("read failure (%ld)", s);
			return TEEC_ERROR_GENERIC;
		}
		if (!s) {
			break;
		}
		sz += s;
		len -= s;
		buf += s;
	}

	SET_MEMREF_SIZE(params + 1, sz);
	return TEEC_SUCCESS;
}

static int tee_fs_write(size_t num_params, struct tee_param *params)
{
	int fd, rc;
	off_t offset;
	size_t len;
	ssize_t sz, s;
	struct fs_file_t *file;
	uint8_t *buf;

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

	file = find_fd(fd);
	if (!file) {
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}

	buf = tee_param_get_mem(params + 1, NULL);
	if (!buf) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	len = MEMREF_SIZE(params + 1);
	sz = 0;
	rc = fs_seek(file, offset, SEEK_SET);
	if (rc == -EINVAL) {
		/*
		 * OP-TEE tries to seek past the end of file. POSIX
		 * allows this, but Zephyr - does not. We need to fill
		 * the file with zeroes to the desired position.
		 */
		off_t cur_offset;
		char zero_buf[8];

		memset(zero_buf, 0, sizeof(zero_buf));
		rc = fs_seek(file, 0, SEEK_END);
		if (rc < 0) {
			LOG_ERR("Failed to seek to the end of file (%d)", rc);
			return TEEC_ERROR_GENERIC;
		}

		cur_offset = fs_tell(file);
		if (cur_offset < 0) {
			LOG_ERR("Failed to get file position (%ld)", cur_offset);
			return TEEC_ERROR_GENERIC;
		}

		while (cur_offset < offset) {
			size_t to_write = MIN(offset - cur_offset,
					      sizeof(zero_buf));
			rc = fs_write(file, zero_buf, to_write);
			if (rc < 0) {
				LOG_ERR("Failed to extend file (%d)", rc);
				return TEEC_ERROR_GENERIC;
			}
			cur_offset += rc;
		}

		rc = 0;
	}
	if (rc < 0) {
		LOG_ERR("invalid offset %ld (%d)", offset, rc);
		return TEEC_ERROR_ITEM_NOT_FOUND;
	}
	while (len > 0) {
		s = fs_write(file, buf, len);
		if (s < 0) {
			LOG_ERR("write failure (%ld)", s);
			return TEEC_ERROR_GENERIC;
		}
		if (!s) {
			break;
		}
		sz += s;
		len -= s;
		buf += s;
	}

	SET_MEMREF_SIZE(params + 1, sz);
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

	file = find_fd(fd);
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

	name = tee_param_get_mem(params + 1, NULL);
	if (!name) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}
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

	name = tee_param_get_mem(params + 1, NULL);
	if (!name) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}
	strncat(path, name, PATH_MAX);

	new_name = tee_param_get_mem(params + 2, NULL);
	if (!new_name) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}
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

	name = tee_param_get_mem(params + 1, NULL);
	if (!name) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}
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
	struct fs_dirent entry;
	struct fs_dir_t *dir;
	size_t len, size;
	int rc;
	char *buf;

	if (num_params != 2) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if ((params[0].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_VALUE_INPUT ||
	    (params[1].attr & TEE_PARAM_ATTR_TYPE_MASK) !=
		TEE_PARAM_ATTR_TYPE_MEMREF_OUTPUT) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	dir = (struct fs_dir_t *)params[0].b;
	buf = tee_param_get_mem(params + 1, &size);
	if (!dir || !buf) {
		return TEEC_ERROR_BAD_PARAMETERS;
	}

	if (params[1].b != size) {
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
	if (size < len) {
		return TEEC_ERROR_SHORT_BUFFER;
	}

	memcpy(buf, entry.name, len);
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
