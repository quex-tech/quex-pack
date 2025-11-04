#include "args.h"
#include "integrity_crypt.h"
#include "mkfs.h"
#include "mount.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len);
// cppcheck-suppress unusedFunction
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len) {
	uint8_t *data_copy = malloc(len + 1);
	memcpy(data_copy, data, len);
	data_copy[len] = '\0';
	int argc = 0;
	char *argv[64] = {0};
	if (len > 0) {
		argv[argc++] = (char *)data_copy;
		for (size_t i = 0; i < len && argc < 63; i++) {
			if (data_copy[i] == '\0') {
				argv[argc++] = (char *)&data_copy[i + 1];
			}
		}
	}

	struct init_args args = {0};
	int err = parse_args(argc, argv, &args);

	if (err) {
		goto cleanup;
	}

	(void)snprintf(NULL, 0, "%s\n", args.key_request_mask);
	(void)snprintf(NULL, 0, "%s\n", args.vault_mrenclave);
	(void)snprintf(NULL, 0, "%s\n", args.workload_path);
	for (ptrdiff_t i = 0; i < args.mount_specs_len; i++) {
		struct mount_spec spec = args.mount_specs[i];
		(void)snprintf(NULL, 0, "%s %s %s %lu\n", spec.source, spec.target, spec.fstype,
		               spec.flags);
	}
	for (ptrdiff_t i = 0; i < args.mkfs_specs_len; i++) {
		struct mkfs_spec spec = args.mkfs_specs[i];
		(void)snprintf(NULL, 0, "%s %s %s\n", spec.dev, spec.fstype, spec.options);
	}
	for (ptrdiff_t i = 0; i < args.integrity_specs_len; i++) {
		struct integrity_spec spec = args.integrity_specs[i];
		(void)snprintf(NULL, 0, "%s %s\n", spec.dev, spec.name);
	}
	for (ptrdiff_t i = 0; i < args.crypt_specs_len; i++) {
		struct crypt_spec spec = args.crypt_specs[i];
		(void)snprintf(NULL, 0, "%s %s\n", spec.dev, spec.name);
	}

cleanup:
	free(data_copy);
	return 0;
}
