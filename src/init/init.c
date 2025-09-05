#include "dm.h"
#include "integrity_crypt.h"
#include "key.h"
#include "mkfs.h"
#include "mount.h"
#include "utils.h"
#include <errno.h>
#include <mbedtls/hkdf.h>
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

const char *workload_path = "/opt/bundle";

const uint8_t hkdf_salt[32] = {0x7f, 0x56, 0x26, 0xb9, 0xf2, 0x95, 0x8c, 0x47, 0xbe, 0x9d, 0x3d,
                               0x7b, 0xb1, 0x6d, 0xb6, 0xf2, 0x84, 0x84, 0x14, 0x25, 0x8a, 0xa7,
                               0x3a, 0x5a, 0x4f, 0x43, 0x9d, 0xe3, 0x18, 0x65, 0xa7, 0x3a};

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
	struct crypt_spec crypt_specs[MAX_DISKS] = {0};
	size_t crypt_specs_len = 0;

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

		if (strcmp(key, "workload") == 0) {
			workload_path = value;
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

		if (strcmp(key, "crypt") == 0) {
			if (crypt_specs_len >= MAX_DISKS) {
				trace("too many disks\n");
				return -1;
			}
			err = parse_crypt_spec((char *)value, &crypt_specs[crypt_specs_len++]);
			if (err) {
				trace("parse_crypt_spec failed: %d\n", err);
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

	unsigned char prk[MBEDTLS_MD_MAX_SIZE];
	const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	const size_t prk_len = mbedtls_md_get_size(md);

	err = mbedtls_hkdf_extract(md, hkdf_salt, sizeof(hkdf_salt), sk, sizeof(sk), prk);
	if (err) {
		trace("mbedtls_hkdf_extract failed: %d\n", err);
		return err;
	}

	for (size_t i = 0; i < integrity_specs_len; i++) {
		uint8_t integrity_sk[32] = {0};
		char integrity_sk_info[512] = {0};
		snprintf(integrity_sk_info, sizeof(integrity_sk_info), "integrity:%s:%s:mac",
		         integrity_specs[i].dev, integrity_specs[i].name);
		err = mbedtls_hkdf_expand(md, prk, prk_len, (uint8_t *)integrity_sk_info,
		                          sizeof(integrity_sk_info), integrity_sk,
		                          sizeof(integrity_sk));
		if (err) {
			trace("mbedtls_hkdf_expand failed: %d\n", err);
			return err;
		}

		uint8_t integrity_journal_crypt_sk[32] = {0};
		char integrity_journal_crypt_sk_info[512] = {0};
		snprintf(integrity_journal_crypt_sk_info, sizeof(integrity_journal_crypt_sk_info),
		         "integrity:%s:%s:journal_crypt", integrity_specs[i].dev,
		         integrity_specs[i].name);
		err = mbedtls_hkdf_expand(
		    md, prk, prk_len, (uint8_t *)integrity_journal_crypt_sk_info,
		    sizeof(integrity_journal_crypt_sk_info), integrity_journal_crypt_sk,
		    sizeof(integrity_journal_crypt_sk));
		if (err) {
			trace("mbedtls_hkdf_expand failed: %d\n", err);
			return err;
		}

		err =
		    setup_integrity(&integrity_specs[i], integrity_sk, integrity_journal_crypt_sk);
		if (err != 0) {
			trace("setup_integrity %s failed: %d\n", integrity_specs[i].dev, err);
			return err;
		}
	}

	for (size_t i = 0; i < crypt_specs_len; i++) {
		uint8_t crypt_sk[32] = {0};
		char crypt_sk_info[512] = {0};
		snprintf(crypt_sk_info, sizeof(crypt_sk_info), "crypt=%s:%s", crypt_specs[i].dev,
		         crypt_specs[i].name);
		err = mbedtls_hkdf_expand(md, prk, prk_len, (uint8_t *)crypt_sk_info,
		                          sizeof(crypt_sk_info), crypt_sk, sizeof(crypt_sk));
		if (err) {
			trace("mbedtls_hkdf_expand failed: %d\n", err);
			return err;
		}

		uint8_t crypt_journal_crypt_sk[32] = {0};
		char crypt_journal_crypt_sk_info[512] = {0};
		snprintf(crypt_journal_crypt_sk_info, sizeof(crypt_journal_crypt_sk_info),
		         "crypt:%s:%s:journal_crypt", crypt_specs[i].dev, crypt_specs[i].name);
		err = mbedtls_hkdf_expand(md, prk, prk_len, (uint8_t *)crypt_journal_crypt_sk_info,
		                          sizeof(crypt_journal_crypt_sk_info),
		                          crypt_journal_crypt_sk, sizeof(crypt_journal_crypt_sk));
		if (err) {
			trace("mbedtls_hkdf_expand failed: %d\n", err);
			return err;
		}

		uint8_t crypt_journal_mac_sk[32] = {0};
		char crypt_journal_mac_sk_info[512] = {0};
		snprintf(crypt_journal_mac_sk_info, sizeof(crypt_journal_mac_sk_info),
		         "crypt:%s:%s:journal_mac", crypt_specs[i].dev, crypt_specs[i].name);
		err = mbedtls_hkdf_expand(md, prk, prk_len, (uint8_t *)crypt_journal_mac_sk_info,
		                          sizeof(crypt_journal_mac_sk_info), crypt_journal_mac_sk,
		                          sizeof(crypt_journal_mac_sk));
		if (err) {
			trace("mbedtls_hkdf_expand failed: %d\n", err);
			return err;
		}

		err = setup_crypt(&crypt_specs[i], crypt_sk, crypt_journal_crypt_sk,
		                  crypt_journal_mac_sk);
		if (err != 0) {
			trace("setup_crypt %s failed: %d\n", crypt_specs[i].dev, err);
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
	strcat(config_path, workload_path);
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
		                           workload_path, "--config", BUNDLE_CONFIG_PATH, "app",
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