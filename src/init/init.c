// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "args.h"
#include "dm.h"
#include "integrity_crypt.h"
#include "key.h"
#include "mkfs.h"
#include "mount.h"
#include "utils.h"
#include <errno.h>
#include <mbedtls/entropy.h>
#include <mbedtls/hkdf.h>
#include <spawn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <tdx_attest.h>
#include <unistd.h>

#define SECRET_KEY_TEMPLATE                                                                        \
	"TD_SECRET_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

#define BUNDLE_CONFIG_PATH "/etc/bundle_config.json"
#define ROOT_PEM_PATH "/etc/root.pem"
#define QUOTE_PATH "/var/data/quote.txt"

static const uint8_t hkdf_salt[32] = {
    0x7f, 0x56, 0x26, 0xb9, 0xf2, 0x95, 0x8c, 0x47, 0xbe, 0x9d, 0x3d, 0x7b, 0xb1, 0x6d, 0xb6, 0xf2,
    0x84, 0x84, 0x14, 0x25, 0x8a, 0xa7, 0x3a, 0x5a, 0x4f, 0x43, 0x9d, 0xe3, 0x18, 0x65, 0xa7, 0x3a};

static int handle_integrity(const uint8_t *prk, size_t prk_len, const mbedtls_md_info_t *md,
                            struct integrity_spec spec) {
	int err = 0;
	uint8_t integrity_sk[32] = {0};
	uint8_t integrity_journal_crypt_sk[32] = {0};
	{
		char integrity_sk_info[512] = {0};
		snprintf(integrity_sk_info, sizeof integrity_sk_info, "integrity:%s:%s:mac",
		         spec.dev, spec.name);
		err = mbedtls_hkdf_expand(md, prk, prk_len, (uint8_t *)integrity_sk_info,
		                          sizeof integrity_sk_info, integrity_sk,
		                          sizeof integrity_sk);
		if (err) {
			trace("mbedtls_hkdf_expand failed: %d\n", err);
			goto cleanup;
		}

		char integrity_journal_crypt_sk_info[512] = {0};
		snprintf(integrity_journal_crypt_sk_info, sizeof integrity_journal_crypt_sk_info,
		         "integrity:%s:%s:journal_crypt", spec.dev, spec.name);
		err = mbedtls_hkdf_expand(
		    md, prk, prk_len, (uint8_t *)integrity_journal_crypt_sk_info,
		    sizeof integrity_journal_crypt_sk_info, integrity_journal_crypt_sk,
		    sizeof integrity_journal_crypt_sk);
		if (err) {
			trace("mbedtls_hkdf_expand failed: %d\n", err);
			goto cleanup;
		}

		err = setup_integrity(&spec, integrity_sk, integrity_journal_crypt_sk);
		if (err) {
			trace("setup_integrity %s failed: %d\n", spec.dev, err);
			goto cleanup;
		}
	}
cleanup:
	mbedtls_platform_zeroize(integrity_sk, 32);
	mbedtls_platform_zeroize(integrity_journal_crypt_sk, 32);

	return err;
}

static int handle_crypt(const uint8_t *prk, size_t prk_len, const mbedtls_md_info_t *md,
                        struct crypt_spec spec) {
	int err = 0;
	uint8_t crypt_sk[32] = {0};
	uint8_t crypt_journal_crypt_sk[32] = {0};
	uint8_t crypt_journal_mac_sk[32] = {0};
	{
		char crypt_sk_info[512] = {0};
		snprintf(crypt_sk_info, sizeof crypt_sk_info, "crypt=%s:%s", spec.dev, spec.name);
		err = mbedtls_hkdf_expand(md, prk, prk_len, (uint8_t *)crypt_sk_info,
		                          strlen(crypt_sk_info), crypt_sk, sizeof crypt_sk);
		if (err) {
			trace("mbedtls_hkdf_expand failed: %d\n", err);
			goto cleanup;
		}

		char crypt_journal_crypt_sk_info[512] = {0};
		snprintf(crypt_journal_crypt_sk_info, sizeof crypt_journal_crypt_sk_info,
		         "crypt:%s:%s:journal_crypt", spec.dev, spec.name);
		err = mbedtls_hkdf_expand(md, prk, prk_len, (uint8_t *)crypt_journal_crypt_sk_info,
		                          strlen(crypt_journal_crypt_sk_info),
		                          crypt_journal_crypt_sk, sizeof crypt_journal_crypt_sk);
		if (err) {
			trace("mbedtls_hkdf_expand failed: %d\n", err);
			goto cleanup;
		}

		char crypt_journal_mac_sk_info[512] = {0};
		snprintf(crypt_journal_mac_sk_info, sizeof crypt_journal_mac_sk_info,
		         "crypt:%s:%s:journal_mac", spec.dev, spec.name);
		err = mbedtls_hkdf_expand(md, prk, prk_len, (uint8_t *)crypt_journal_mac_sk_info,
		                          strlen(crypt_journal_mac_sk_info), crypt_journal_mac_sk,
		                          sizeof crypt_journal_mac_sk);
		if (err) {
			trace("mbedtls_hkdf_expand failed: %d\n", err);
			goto cleanup;
		}

		err = setup_crypt(&spec, crypt_sk, crypt_journal_crypt_sk, crypt_journal_mac_sk);
		if (err) {
			trace("setup_crypt %s failed: %d\n", spec.dev, err);
			goto cleanup;
		}
	}
cleanup:
	mbedtls_platform_zeroize(crypt_sk, 32);
	mbedtls_platform_zeroize(crypt_journal_crypt_sk, 32);
	mbedtls_platform_zeroize(crypt_journal_mac_sk, 32);

	return err;
}

static int save_quote(const uint8_t pk[64], const char *path) {
	uint8_t *p_quote_buf = NULL;
	tdx_report_data_t report_data = {0};
	memcpy(&report_data, pk, 64);

	tdx_uuid_t selected_att_key_id = {0};
	uint32_t quote_size = 0;
	int err = 0;
	tdx_attest_error_t attest_err = tdx_att_get_quote(
	    &report_data, NULL, 0, &selected_att_key_id, &p_quote_buf, &quote_size, 0);
	if (attest_err != TDX_ATTEST_SUCCESS) {
		trace("tdx_att_get_quote failed: %d\n", err);
		err = -1;
		goto cleanup;
	}

	err = write_hex_to_file(path, p_quote_buf, quote_size);
	if (err) {
		trace("write_hex_to_file failed: %d\n", err);
		goto cleanup;
	}

cleanup:
	if (p_quote_buf) {
		tdx_att_free_quote(p_quote_buf);
	}
	return err;
}

static int run_crun(const char *workload_path) {
	int err = 0;
	char *arg4 = NULL;
	{
		char arg0[] = "crun";
		char arg1[] = "run";
		char arg2[] = "--no-pivot";
		char arg3[] = "--bundle";
		arg4 = strdup(workload_path);
		if (!arg4) {
			err = -1;
			goto cleanup;
		}
		char arg5[] = "--config";
		char arg6[] = BUNDLE_CONFIG_PATH;
		char arg7[] = "app";
		char *argv[] = {arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7, NULL};
		char *envp[] = {NULL};

		pid_t pid;
		err = posix_spawn(&pid, "/usr/bin/crun", NULL, NULL, argv, envp);
		if (err) {
			trace("posix_spawn failed: %s\n", strerror(err));
			goto cleanup;
		}

		trace("Waiting for crun to exit...\n");

		int status;
		pid_t waitpid_ret = waitpid(pid, &status, 0);
		if (waitpid_ret < 0) {
			err = -errno;
			trace("waitpid failed: %s\n", strerror(errno));
			goto cleanup;
		}

		trace("crun exited with status %d\n", status);
	}
cleanup:
	free(arg4);
	return err;
}

static int init(int argc, char *argv[]) {
	umask(S_IRWXG | S_IRWXO);
	int err = 0;
	uint8_t prk[MBEDTLS_MD_MAX_SIZE] = {0};
	uint8_t sk[32] = {0};
	uint8_t pk[64] = {0};
	{
		err = prctl(PR_SET_DUMPABLE, 0);
		if (err) {
			trace("prctl failed: %s\n", strerror(errno));
			goto cleanup;
		}

		struct init_args parameters = {
		    .key_request_mask = "", .vault_mrenclave = "", .workload_path = "/opt/bundle"};

		parse_args(argc, argv, &parameters);

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
		err = mount("none", "/sys/kernel/config", "configfs",
		            MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
		if (err) {
			trace("mount /sys/kernel/config failed: %s\n", strerror(errno));
			goto cleanup;
		}
		err = mount("none", "/sys/fs/cgroup", "cgroup2", MS_NOSUID | MS_NODEV | MS_NOEXEC,
		            NULL);
		if (err) {
			trace("mount /sys/fs/cgroup failed: %s\n", strerror(errno));
			goto cleanup;
		}

		err = get_keys(parameters.key_request_mask, parameters.vault_mrenclave,
		               ROOT_PEM_PATH, mbedtls_entropy_func, sk, pk);
		if (err) {
			trace("get_keys failed: %d\n", err);
			goto cleanup;
		}

		err = save_quote(pk, QUOTE_PATH);
		if (err) {
			trace("save_quote failed: %d\n", err);
			goto cleanup;
		}

		const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
		const size_t prk_len = mbedtls_md_get_size(md);

		err = mbedtls_hkdf_extract(md, hkdf_salt, sizeof hkdf_salt, sk, sizeof sk, prk);
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
			err = mkfs(&parameters.mkfs_specs[i]);
			if (err) {
				trace("mkfs %s failed: %d\n", parameters.mkfs_specs[i].dev, err);
				goto cleanup;
			}
		}

		for (size_t i = 0; i < parameters.mount_specs_len; i++) {
			err = mount(parameters.mount_specs[i].source,
			            parameters.mount_specs[i].target,
			            parameters.mount_specs[i].fstype,
			            parameters.mount_specs[i].flags, NULL);
			if (err) {
				trace("mount %s failed: %s\n", parameters.mount_specs[i].target,
				      strerror(errno));
				goto cleanup;
			}
		}

		char config_path[256] = {0};
		snprintf(config_path, sizeof config_path, "%s/config.json",
		         parameters.workload_path);
		err = copy_file(config_path, BUNDLE_CONFIG_PATH);
		if (err) {
			trace("Cannot copy %s to %s\n", config_path, BUNDLE_CONFIG_PATH);
			goto cleanup;
		}

		char key_env_var[] = SECRET_KEY_TEMPLATE;
		write_hex(sk, sizeof sk, key_env_var + strlen("TD_SECRET_KEY="));
		replace_in_file(BUNDLE_CONFIG_PATH, SECRET_KEY_TEMPLATE, key_env_var);
		mbedtls_platform_zeroize(key_env_var, sizeof SECRET_KEY_TEMPLATE);

		err = run_crun(parameters.workload_path);
		if (err) {
			trace("run_crun failed: %d\n", err);
			goto cleanup;
		}
	}
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
}
