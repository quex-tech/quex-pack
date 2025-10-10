// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "dm.h"
#include "integrity_crypt.h"
#include "key.h"
#include "mkfs.h"
#include "mount.h"
#include "tdx.h"
#include "utils.h"
#include <errno.h>
#include <mbedtls/entropy.h>
#include <mbedtls/hkdf.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define SECRET_KEY_TEMPLATE                                                                        \
	"TD_SECRET_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

#define BUNDLE_CONFIG_PATH "/etc/bundle_config.json"
#define ROOT_PEM_PATH "/etc/root.pem"
#define QUOTE_PATH "/var/data/quote.txt"

#define MAX_DISKS 8

const uint8_t hkdf_salt[32] = {0x7f, 0x56, 0x26, 0xb9, 0xf2, 0x95, 0x8c, 0x47, 0xbe, 0x9d, 0x3d,
                               0x7b, 0xb1, 0x6d, 0xb6, 0xf2, 0x84, 0x84, 0x14, 0x25, 0x8a, 0xa7,
                               0x3a, 0x5a, 0x4f, 0x43, 0x9d, 0xe3, 0x18, 0x65, 0xa7, 0x3a};

struct init_parameters {
	const char *key_request_mask;
	const char *vault_mrenclave;
	const char *workload_path;
	struct mount_spec mount_specs[MAX_DISKS];
	size_t mount_specs_len;
	struct mkfs_spec mkfs_specs[MAX_DISKS];
	size_t mkfs_specs_len;
	struct integrity_spec integrity_specs[MAX_DISKS];
	size_t integrity_specs_len;
	struct crypt_spec crypt_specs[MAX_DISKS];
	size_t crypt_specs_len;
};

static int parse_init_parameter(char *arg, struct init_parameters *parsed) {
	int err = 0;

	char *eq = strchr(arg, '=');
	if (!eq) {
		return 0;
	}

	const char *value = eq + 1;

	if (strncmp(arg, "key_request_mask=", strlen("key_request_mask=")) == 0) {
		parsed->key_request_mask = value;
		return 0;
	}

	if (strncmp(arg, "vault_mrenclave=", strlen("vault_mrenclave=")) == 0) {
		parsed->vault_mrenclave = value;
		return 0;
	}

	if (strncmp(arg, "workload=", strlen("workload=")) == 0) {
		if (strlen(value) > 192) {
			trace("Workload path is too long\n");
			return -1;
		}
		parsed->workload_path = value;
		return 0;
	}

	if (strncmp(arg, "integrity=", strlen("integrity=")) == 0) {
		if (parsed->integrity_specs_len >= MAX_DISKS) {
			trace("Too many disks\n");
			return -1;
		}
		err = parse_integrity_spec(
		    (char *)value, &(parsed->integrity_specs[parsed->integrity_specs_len++]));
		if (err) {
			trace("parse_integrity_spec failed: %d\n", err);
			return err;
		}
		return 0;
	}

	if (strncmp(arg, "crypt=", strlen("crypt=")) == 0) {
		if (parsed->crypt_specs_len >= MAX_DISKS) {
			trace("Too many disks\n");
			return -1;
		}
		err = parse_crypt_spec((char *)value,
		                       &(parsed->crypt_specs[parsed->crypt_specs_len++]));
		if (err) {
			trace("parse_crypt_spec failed: %d\n", err);
			return err;
		}
		return 0;
	}

	if (strncmp(arg, "mkfs=", strlen("mkfs=")) == 0) {
		if (parsed->mkfs_specs_len >= MAX_DISKS) {
			trace("Too many disks\n");
			return -1;
		}
		err =
		    parse_mkfs_spec((char *)value, &(parsed->mkfs_specs[parsed->mkfs_specs_len++]));
		if (err) {
			trace("parse_mkfs_spec failed: %d\n", err);
			return err;
		}
		return 0;
	}

	if (strncmp(arg, "mount=", strlen("mount=")) == 0) {
		if (parsed->mount_specs_len >= MAX_DISKS) {
			trace("Too many disks\n");
			return -1;
		}
		err = parse_mount_spec((char *)value,
		                       &(parsed->mount_specs[parsed->mount_specs_len++]));
		if (err) {
			trace("parse_mount_spec failed: %d\n", err);
			return err;
		}
		return 0;
	}

	return 0;
}

static int handle_integrity(unsigned char *prk, size_t prk_len, const mbedtls_md_info_t *md,
                            struct integrity_spec spec) {
	uint8_t integrity_sk[32] = {0};
	char integrity_sk_info[512] = {0};
	snprintf(integrity_sk_info, sizeof(integrity_sk_info), "integrity:%s:%s:mac", spec.dev,
	         spec.name);
	int err =
	    mbedtls_hkdf_expand(md, prk, prk_len, (uint8_t *)integrity_sk_info,
	                        sizeof(integrity_sk_info), integrity_sk, sizeof(integrity_sk));
	if (err) {
		trace("mbedtls_hkdf_expand failed: %d\n", err);
		goto cleanup;
	}

	uint8_t integrity_journal_crypt_sk[32] = {0};
	char integrity_journal_crypt_sk_info[512] = {0};
	snprintf(integrity_journal_crypt_sk_info, sizeof(integrity_journal_crypt_sk_info),
	         "integrity:%s:%s:journal_crypt", spec.dev, spec.name);
	err = mbedtls_hkdf_expand(md, prk, prk_len, (uint8_t *)integrity_journal_crypt_sk_info,
	                          sizeof(integrity_journal_crypt_sk_info),
	                          integrity_journal_crypt_sk, sizeof(integrity_journal_crypt_sk));
	if (err) {
		trace("mbedtls_hkdf_expand failed: %d\n", err);
		goto cleanup;
	}

	err = setup_integrity(&spec, integrity_sk, integrity_journal_crypt_sk);
	if (err) {
		trace("setup_integrity %s failed: %d\n", spec.dev, err);
		goto cleanup;
	}

cleanup:
	mbedtls_platform_zeroize(integrity_sk, 32);
	mbedtls_platform_zeroize(integrity_journal_crypt_sk, 32);

	return err;
}

static int handle_crypt(unsigned char *prk, size_t prk_len, const mbedtls_md_info_t *md,
                        struct crypt_spec spec) {
	int err = 0;
	uint8_t crypt_sk[32] = {0};
	char crypt_sk_info[512] = {0};
	snprintf(crypt_sk_info, sizeof(crypt_sk_info), "crypt=%s:%s", spec.dev, spec.name);
	err = mbedtls_hkdf_expand(md, prk, prk_len, (uint8_t *)crypt_sk_info, strlen(crypt_sk_info),
	                          crypt_sk, sizeof(crypt_sk));
	if (err) {
		trace("mbedtls_hkdf_expand failed: %d\n", err);
		goto cleanup;
	}

	uint8_t crypt_journal_crypt_sk[32] = {0};
	char crypt_journal_crypt_sk_info[512] = {0};
	snprintf(crypt_journal_crypt_sk_info, sizeof(crypt_journal_crypt_sk_info),
	         "crypt:%s:%s:journal_crypt", spec.dev, spec.name);
	err = mbedtls_hkdf_expand(md, prk, prk_len, (uint8_t *)crypt_journal_crypt_sk_info,
	                          strlen(crypt_journal_crypt_sk_info), crypt_journal_crypt_sk,
	                          sizeof(crypt_journal_crypt_sk));
	if (err) {
		trace("mbedtls_hkdf_expand failed: %d\n", err);
		goto cleanup;
	}

	uint8_t crypt_journal_mac_sk[32] = {0};
	char crypt_journal_mac_sk_info[512] = {0};
	snprintf(crypt_journal_mac_sk_info, sizeof(crypt_journal_mac_sk_info),
	         "crypt:%s:%s:journal_mac", spec.dev, spec.name);
	err = mbedtls_hkdf_expand(md, prk, prk_len, (uint8_t *)crypt_journal_mac_sk_info,
	                          strlen(crypt_journal_mac_sk_info), crypt_journal_mac_sk,
	                          sizeof(crypt_journal_mac_sk));
	if (err) {
		trace("mbedtls_hkdf_expand failed: %d\n", err);
		goto cleanup;
	}

	err = setup_crypt(&spec, crypt_sk, crypt_journal_crypt_sk, crypt_journal_mac_sk);
	if (err) {
		trace("setup_crypt %s failed: %d\n", spec.dev, err);
		goto cleanup;
	}

cleanup:
	mbedtls_platform_zeroize(crypt_sk, 32);
	mbedtls_platform_zeroize(crypt_journal_crypt_sk, 32);
	mbedtls_platform_zeroize(crypt_journal_mac_sk, 32);

	return err;
}

int init(int argc, char *argv[]) {
	int err = 0;
	struct init_parameters parameters = {
	    .key_request_mask = "", .vault_mrenclave = "", .workload_path = "/opt/bundle"};

	umask(0077);
	err = prctl(PR_SET_DUMPABLE, 0);
	if (err) {
		trace("prctl failed: %s\n", strerror(errno));
		goto cleanup;
	}

	for (int i = 1; i < argc; i++) {
		trace("argv[%d] = %s\n", i, argv[i]);
		err = parse_init_parameter(argv[i], &parameters);
		if (err) {
			goto cleanup;
		}
	}

	err = mount("devtmpfs", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, "mode=0755");
	if (err) {
		trace("mount /dev failed: %s\n", strerror(errno));
		goto cleanup;
	}
	err = mount("none", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
	if (err) {
		trace("mount /proc failed: %s\n", strerror(errno));
		goto cleanup;
	}
	err = mount("none", "/sys", "sysfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
	if (err) {
		trace("mount /sys failed: %s\n", strerror(errno));
		goto cleanup;
	}
	err =
	    mount("none", "/sys/kernel/config", "configfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
	if (err) {
		trace("mount /sys/kernel/config failed: %s\n", strerror(errno));
		goto cleanup;
	}
	err = mount("none", "/sys/fs/cgroup", "cgroup2", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
	if (err) {
		trace("mount /sys/fs/cgroup failed: %s\n", strerror(errno));
		goto cleanup;
	}

	const struct tdx_iface tdx_ops = {
	    .get_quote = tdx_att_get_quote,
	    .free_quote = tdx_att_free_quote,
	    .get_report = tdx_att_get_report,
	};

	uint8_t sk[32] = {0};
	err = get_sk(sk, parameters.key_request_mask, parameters.vault_mrenclave, ROOT_PEM_PATH,
	             QUOTE_PATH, &tdx_ops, mbedtls_entropy_func);
	if (err) {
		trace("get_sk failed: %d\n", err);
		goto cleanup;
	}

	unsigned char prk[MBEDTLS_MD_MAX_SIZE];
	const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
	const size_t prk_len = mbedtls_md_get_size(md);

	err = mbedtls_hkdf_extract(md, hkdf_salt, sizeof(hkdf_salt), sk, sizeof(sk), prk);
	if (err) {
		trace("mbedtls_hkdf_extract failed: %d\n", err);
		goto cleanup;
	}

	for (size_t i = 0; i < parameters.integrity_specs_len; i++) {
		err = handle_integrity(prk, prk_len, md, parameters.integrity_specs[i]);
		if (err) {
			trace("handle_integrity failed: %d\n", err);
			goto cleanup;
		}
	}

	for (size_t i = 0; i < parameters.crypt_specs_len; i++) {
		err = handle_crypt(prk, prk_len, md, parameters.crypt_specs[i]);
		if (err) {
			trace("handle_crypt failed: %d\n", err);
			goto cleanup;
		}
	}

	update_device_nodes();

	for (size_t i = 0; i < parameters.mkfs_specs_len; i++) {
		err = mkfs(&(parameters.mkfs_specs[i]));
		if (err) {
			trace("mkfs %s failed: %d\n", parameters.mkfs_specs[i].dev, err);
			goto cleanup;
		}
	}

	for (size_t i = 0; i < parameters.mount_specs_len; i++) {
		err =
		    mount(parameters.mount_specs[i].source, parameters.mount_specs[i].target,
		          parameters.mount_specs[i].fstype, parameters.mount_specs[i].flags, NULL);
		if (err) {
			trace("mount %s failed: %s\n", parameters.mount_specs[i].target,
			      strerror(errno));
			goto cleanup;
		}
	}

	char config_path[256] = {0};
	snprintf(config_path, sizeof(config_path), "%s/config.json", parameters.workload_path);
	err = copy_file(config_path, BUNDLE_CONFIG_PATH);
	if (err) {
		trace("Cannot copy %s to %s\n", config_path, BUNDLE_CONFIG_PATH);
		goto cleanup;
	}

	char key_env_var[] = SECRET_KEY_TEMPLATE;
	write_hex(sk, sizeof(sk), key_env_var + strlen("TD_SECRET_KEY="));
	replace_in_file(BUNDLE_CONFIG_PATH, SECRET_KEY_TEMPLATE, key_env_var);
	mbedtls_platform_zeroize(key_env_var, sizeof(SECRET_KEY_TEMPLATE));

	const char *exec_argv[] = {"crun",
	                           "run",
	                           "--no-pivot",
	                           "--bundle",
	                           parameters.workload_path,
	                           "--config",
	                           BUNDLE_CONFIG_PATH,
	                           "app",
	                           NULL};
	const char *exec_envp[] = {NULL};

	pid_t pid;
	err = posix_spawn(&pid, "/usr/bin/crun", NULL, NULL, (char *const *)exec_argv,
	                  (char *const *)exec_envp);
	if (err) {
		trace("posix_spawn failed: %s\n", strerror(err));
		goto cleanup;
	}

	trace("Waiting for crun to exit...\n");

	int status;
	err = waitpid(pid, &status, 0);
	if (err) {
		trace("waitpid failed: %s\n", strerror(errno));
		goto cleanup;
	}

	trace("crun exited with status %d\n", status);

cleanup:
	mbedtls_platform_zeroize(sk, 32);
	mbedtls_platform_zeroize(prk, MBEDTLS_MD_MAX_SIZE);
	return err;
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