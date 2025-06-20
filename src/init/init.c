#include "key.h"
#include "storage.h"
#include "utils.h"
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define SECRET_KEY_TEMPLATE                                                                        \
	"TD_SECRET_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

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

int main(void) {
	int ret;
	if ((ret = mount("devtmpfs", "/dev", "devtmpfs", 0, NULL)) != 0) {
		perror("mount /dev");
		return -1;
	}
	if ((ret = mount("none", "/proc", "proc", 0, NULL)) != 0) {
		perror("mount /proc");
		return -1;
	}
	if ((ret = mount("none", "/sys", "sysfs", 0, NULL)) != 0) {
		perror("mount /sys");
		return -1;
	}
	if ((ret = mount("none", "/sys/kernel/config", "configfs", 0, NULL)) != 0) {
		perror("mount /sys/kernel/config");
		return -1;
	}
	if ((ret = mount("none", "/sys/fs/cgroup", "cgroup2", 0, NULL)) != 0) {
		perror("mount /sys/fs/cgroup");
		return -1;
	}

	uint8_t sk[32] = {0};
	if (get_sk(sk) != 0) {
		return -1;
	}

	char *bundle_path = locate_bundle();
	if (bundle_path == NULL) {
		return -1;
	}

	char config_path[256] = {0};
	strcat(config_path, bundle_path);
	strcat(config_path, "/config.json");
	if (copy_file(config_path, "/etc/bundle_config.json") != 0) {
		return -1;
	}

	setup_storage(sk, "storage", "storage");

	char key_env_var[] = SECRET_KEY_TEMPLATE;
	write_hex(sk, sizeof(sk), key_env_var + strlen("TD_SECRET_KEY="));
	replace_in_file("/etc/bundle_config.json", SECRET_KEY_TEMPLATE, key_env_var);

	pid_t pid = vfork();

	if (pid == 0) {
		char *exec_argv[] = {"crun",
		                     "run",
		                     "--no-pivot",
		                     "--bundle",
		                     bundle_path,
		                     "--config",
		                     "/etc/bundle_config.json",
		                     "app",
		                     NULL};
		char *exec_envp[] = {NULL};
		execve("/usr/bin/crun", exec_argv, exec_envp);
	} else if (pid > 0) {
		trace("Waiting for crun to exit...\n");
		int status;
		if (waitpid(pid, &status, 0) == 0) {
			trace("crun exited with status %d\n", status);
		} else {
			perror("waitpid failed");
		}
	} else {
		perror("vfork failed");
	}

	while (1) {
		pause();
	}

	return 0;
}
