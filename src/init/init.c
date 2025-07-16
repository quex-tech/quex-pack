#include "key.h"
#include "storage.h"
#include "utils.h"
#include <errno.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define SECRET_KEY_TEMPLATE                                                                        \
	"TD_SECRET_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

#define BUNDLE_CONFIG_PATH "/etc/bundle_config.json"

char *locate_bundle() {
	struct stat st;
	if (stat("/opt/bundle", &st) == 0) {
		return "/opt/bundle";
	}

	if (stat("/dev/dm-0", &st) == 0 &&
	    mount("/dev/dm-0", "/mnt/bundle", "squashfs", MS_RDONLY, NULL) == 0) {
		return "/mnt/bundle";
	}

	return NULL;
}

int main(int argc, char *argv[]) {
	int err;

	const char *key_request_mask = "";
	const char *vault_mrenclave = "";

	for (int i = 1; i < argc; i++) {
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
	}

	trace("key_request_mask = %s\n", key_request_mask);
	trace("vault_mrenclave = %s\n", vault_mrenclave);

	if ((err = mount("devtmpfs", "/dev", "devtmpfs", 0, NULL)) != 0) {
		trace("mount /dev failed: %s\n", strerror(errno));
		return -1;
	}
	if ((err = mount("none", "/proc", "proc", 0, NULL)) != 0) {
		trace("mount /proc failed: %s\n", strerror(errno));
		return -1;
	}
	if ((err = mount("none", "/sys", "sysfs", 0, NULL)) != 0) {
		trace("mount /sys failed: %s\n", strerror(errno));
		return -1;
	}
	if ((err = mount("none", "/sys/kernel/config", "configfs", 0, NULL)) != 0) {
		trace("mount /sys/kernel/config failed: %s\n", strerror(errno));
		return -1;
	}
	if ((err = mount("none", "/sys/fs/cgroup", "cgroup2", 0, NULL)) != 0) {
		trace("mount /sys/fs/cgroup failed: %s\n", strerror(errno));
		return -1;
	}

	uint8_t sk[32] = {0};
	if ((err = get_sk(sk, key_request_mask, vault_mrenclave)) != 0) {
		trace("get_sk failed: %d\n", err);
		return -1;
	}

	char *bundle_path = locate_bundle();
	if (bundle_path == NULL) {
		trace("Cannot locate bundle\n");
		return -1;
	}

	char config_path[256] = {0};
	strcat(config_path, bundle_path);
	strcat(config_path, "/config.json");
	if ((err = copy_file(config_path, BUNDLE_CONFIG_PATH)) != 0) {
		trace("Cannot copy %s to %s\n", config_path, BUNDLE_CONFIG_PATH);
		return -1;
	}

	setup_storage(sk, "storage", "/mnt/storage");

	char key_env_var[] = SECRET_KEY_TEMPLATE;
	write_hex(sk, sizeof(sk), key_env_var + strlen("TD_SECRET_KEY="));
	replace_in_file(BUNDLE_CONFIG_PATH, SECRET_KEY_TEMPLATE, key_env_var);

	pid_t pid = vfork();

	if (pid == 0) {
		char *exec_argv[] = {"crun",      "run",      "--no-pivot",       "--bundle",
		                     bundle_path, "--config", BUNDLE_CONFIG_PATH, "app",
		                     NULL};
		char *exec_envp[] = {NULL};
		execve("/usr/bin/crun", exec_argv, exec_envp);
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
	}

	while (1) {
		pause();
	}

	return 0;
}
