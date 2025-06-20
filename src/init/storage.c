#include "storage.h"
#include "integrity.h"
#include "utils.h"
#include <dirent.h>
#include <errno.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#include <ext2fs/ext2_fs.h>
#pragma GCC diagnostic pop
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wsign-conversion"
#pragma GCC diagnostic ignored "-Wconversion"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#include <ext2fs/ext2fs.h>
#pragma GCC diagnostic pop
#include <fcntl.h>
#include <inttypes.h>
#include <libdevmapper.h>
#include <linux/fs.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>

static int find_disk_by_serial(const char *serial, char *dev_path, size_t dev_path_len) {
	trace("Searching for a disk with serial %s\n", serial);

	if (!serial || !*serial || !dev_path || dev_path_len == 0) {
		return -1;
	}

	DIR *dir = opendir("/sys/block");
	if (!dir) {
		trace("opendir failed: %s\n", strerror(errno));
		return -errno;
	}

	struct dirent *entry;
	char path[1024];
	char read_serial[256] = {0};

	while ((entry = readdir(dir))) {
		snprintf(path, sizeof(path), "/sys/block/%s/serial", entry->d_name);

		FILE *fp = fopen(path, "r");
		if (!fp) {
			trace("Cannot open %s\n", path);
			continue;
		}

		if (fgets(read_serial, sizeof(read_serial), fp)) {
			read_serial[strcspn(read_serial, "\n")] = '\0';

			trace("Read serial '%s' of %s\n", read_serial, path);

			if (strcmp(read_serial, serial) == 0) {
				size_t needed = strlen("/dev/") + strlen(entry->d_name) + 1;
				if (needed > dev_path_len) {
					fclose(fp);
					closedir(dir);
					return -1;
				}

				snprintf(dev_path, dev_path_len, "/dev/%s", entry->d_name);
				fclose(fp);
				closedir(dir);
				return 0;
			}
		}
		fclose(fp);
	}

	closedir(dir);
	return -1;
}

static bool device_is_ext4(const char *dev) {
	ext2_filsys fs = NULL;
	errcode_t err;

	err = ext2fs_open(dev, 0, 0, 0, unix_io_manager, &fs);
	if (err) {
		return false;
	}

	if (fs->super->s_magic != EXT2_SUPER_MAGIC) {
		ext2fs_close(fs);
		return false;
	}

	bool has_ext4_features = ext2fs_has_feature_extents(fs->super) &&
	                         ext2fs_has_feature_64bit(fs->super) &&
	                         ext2fs_has_feature_metadata_csum(fs->super);

	ext2fs_close(fs);

	return has_ext4_features;
}

static int mkfs_ext4(const char *dev) {
	pid_t pid = fork();
	if (pid < 0) {
		int err = errno;
		trace("fork failed: %s\n", strerror(err));
		return -err;
	}

	if (pid == 0) {
		execl("/usr/bin/mke2fs", "mke2fs", "-t", "ext4", "-F", "-q", "-L", "demo-ext4",
		      "-O", "metadata_csum,64bit,extent,huge_file,dir_index", dev, (char *)NULL);
		trace("exec failed: %s\n", strerror(errno));
		_exit(127);
	}

	int status;
	if (waitpid(pid, &status, 0) < 0) {
		int err = errno;
		trace("waitpid failed: %s\n", strerror(err));
		return -err;
	}

	trace("mke2fs exit status: %d\n", status);

	return (WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

int setup_storage(const uint8_t secret_key[32], const char *serial, const char *mapper_name) {
	trace("Setting up storage...\n");
	int err = 0;

	char dev_path[64];
	err = find_disk_by_serial(serial, dev_path, sizeof(dev_path));
	if (err) {
		trace("Cannot find disk by serial %s: %d\n", serial, err);
		return err;
	}

	err = setup_integrity(mapper_name, dev_path, secret_key);
	if (err) {
		trace("Cannot map device %s to %s: %d\n", dev_path, mapper_name, err);
		return err;
	}

	char mapped_dev_path[64] = {0};
	snprintf(mapped_dev_path, sizeof(mapped_dev_path), "/dev/mapper/%s", mapper_name);

	if (!device_is_ext4(mapped_dev_path)) {
		trace("No ext4. Formatting...\n");
		err = mkfs_ext4(mapped_dev_path);
		if (err) {
			trace("mkfs_ext4 failed: %d\n", err);
			return err;
		}
	} else {
		trace("Already has ext4\n");
	}

	int mount_err = mount(mapped_dev_path, "/mnt/storage", "ext4", 0, NULL);
	if (mount_err == -1) {
		err = errno;
		trace("mount %s failed: %s\n", mapped_dev_path, strerror(err));
		return -err;
	}

	trace("Device %s ready\n", mapped_dev_path);
	return err;
}
