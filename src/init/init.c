#include "dm.h"
#include "integrity.h"
#include "key.h"
#include "mkfs.h"
#include "mount.h"
#include "utils.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define SECRET_KEY_TEMPLATE                                                                        \
	"TD_SECRET_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

#define BUNDLE_CONFIG_PATH "/etc/bundle_config.json"

#define MAX_DISKS 8

const char *payload_path = "/opt/bundle";

int init(int argc, char *argv[]) {
	int err = 0;
	const char *key_request_mask = "";
	const char *vault_mrenclave = "";
	struct mount_spec mount_specs[MAX_DISKS] = {0};
	size_t mount_specs_len = 0;
	struct mkfs_spec mkfs_specs[MAX_DISKS] = {0};
	size_t mkfs_specs_len = 0;
	struct integrity_spec integrity_specs[MAX_DISKS] = {0};
	size_t integrity_specs_len = 0;

	for (int i = 1; i < argc; i++) {
		trace("argv[%d] = %s\n", i, argv[i]);

		char *eq = strchr(argv[i], '=');
		if (!eq) {
			continue;
		}

		*eq = '\0';
		const char *key = argv[i];
		const char *value = eq + 1;

		if (strcmp(key, "key_request_mask") == 0) {
			key_request_mask = value;
			continue;
		}

		if (strcmp(key, "vault_mrenclave") == 0) {
			vault_mrenclave = value;
			continue;
		}

		if (strcmp(key, "payload") == 0) {
			payload_path = value;
			continue;
		}

		if (strcmp(key, "integrity") == 0) {
			if (integrity_specs_len >= MAX_DISKS) {
				trace("too many disks\n");
				return -1;
			}
			err = parse_integrity_spec((char *)value,
			                           &integrity_specs[integrity_specs_len++]);
			if (err) {
				trace("parse_integrity_spec failed: %d\n", err);
				return err;
			}
			continue;
		}

		if (strcmp(key, "mkfs") == 0) {
			if (mkfs_specs_len >= MAX_DISKS) {
				trace("too many disks\n");
				return -1;
			}
			err = parse_mkfs_spec((char *)value, &mkfs_specs[mkfs_specs_len++]);
			if (err) {
				trace("parse_mkfs_spec failed: %d\n", err);
				return err;
			}
			continue;
		}

		if (strcmp(key, "mount") == 0) {
			if (mount_specs_len >= MAX_DISKS) {
				trace("too many disks\n");
				return -1;
			}
			err = parse_mount_spec((char *)value, &mount_specs[mount_specs_len++]);
			if (err) {
				trace("parse_mount_spec failed: %d\n", err);
				return err;
			}
			continue;
		}
	}

	if ((err = mount("devtmpfs", "/dev", "devtmpfs", 0, NULL)) != 0) {
		trace("mount /dev failed: %s\n", strerror(errno));
		return err;
	}
	if ((err = mount("none", "/proc", "proc", 0, NULL)) != 0) {
		trace("mount /proc failed: %s\n", strerror(errno));
		return err;
	}
	if ((err = mount("none", "/sys", "sysfs", 0, NULL)) != 0) {
		trace("mount /sys failed: %s\n", strerror(errno));
		return err;
	}
	if ((err = mount("none", "/sys/kernel/config", "configfs", 0, NULL)) != 0) {
		trace("mount /sys/kernel/config failed: %s\n", strerror(errno));
		return err;
	}
	if ((err = mount("none", "/sys/fs/cgroup", "cgroup2", 0, NULL)) != 0) {
		trace("mount /sys/fs/cgroup failed: %s\n", strerror(errno));
		return err;
	}

	uint8_t sk[32] = {0};
	if ((err = get_sk(sk, key_request_mask, vault_mrenclave)) != 0) {
		trace("get_sk failed: %d\n", err);
		return err;
	}

	for (size_t i = 0; i < integrity_specs_len; i++) {
		err = setup_integrity(&integrity_specs[i], sk);
		if (err != 0) {
			trace("setup_integrity %s failed: %d\n", integrity_specs[i].dev, err);
			return err;
		}
	}

	update_device_nodes();

	for (size_t i = 0; i < mkfs_specs_len; i++) {
		err = mkfs(&mkfs_specs[i]);
		if (err != 0) {
			trace("mkfs %s failed: %d\n", mkfs_specs[i].dev, err);
			return err;
		}
	}

	for (size_t i = 0; i < mount_specs_len; i++) {
		err = mount(mount_specs[i].source, mount_specs[i].target, mount_specs[i].fstype,
		            mount_specs[i].flags, NULL);
		if (err != 0) {
			trace("mount %s failed: %s\n", mount_specs[i].target, strerror(errno));
			return err;
		}
	}

	char config_path[256] = {0};
	strcat(config_path, payload_path);
	strcat(config_path, "/config.json");
	if ((err = copy_file(config_path, BUNDLE_CONFIG_PATH)) != 0) {
		trace("Cannot copy %s to %s\n", config_path, BUNDLE_CONFIG_PATH);
		return err;
	}

	char key_env_var[] = SECRET_KEY_TEMPLATE;
	write_hex(sk, sizeof(sk), key_env_var + strlen("TD_SECRET_KEY="));
	replace_in_file(BUNDLE_CONFIG_PATH, SECRET_KEY_TEMPLATE, key_env_var);

	pid_t pid = vfork();

	if (pid == 0) {
		const char *exec_argv[] = {"crun",       "run",      "--no-pivot",       "--bundle",
		                           payload_path, "--config", BUNDLE_CONFIG_PATH, "app",
		                           NULL};
		const char *exec_envp[] = {NULL};
		execve("/usr/bin/crun", (char *const *)exec_argv, (char *const *)exec_envp);
	} else if (pid > 0) {
		trace("Waiting for crun to exit...\n");
		int status;
		if (waitpid(pid, &status, 0) == 0) {
			trace("crun exited with status %d\n", status);
		} else {
			trace("waitpid failed: %s\n", strerror(errno));
		}
	} else {
		trace("vfork failed: %s\n", strerror(errno));
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[]) {
	int err = init(argc, argv);
	if (err) {
		trace("init failed: %d\n", err);
	}

	while (1) {
		pause();
	}

	return 0;
}