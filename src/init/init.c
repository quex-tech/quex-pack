#include "key.h"
#include "utils.h"
#include <string.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <unistd.h>

#define SECRET_KEY_TEMPLATE                                                                        \
	"TD_SECRET_KEY=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"

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

	char key_env_var[] = SECRET_KEY_TEMPLATE;
	write_hex(sk, sizeof(sk), key_env_var + strlen("TD_SECRET_KEY="));
	replace_in_file("/opt/bundle/config.json", SECRET_KEY_TEMPLATE, key_env_var);

	pid_t pid = vfork();

	if (pid == 0) {
		char *exec_argv[] = {"crun",        "run", "--no-pivot", "--bundle",
		                     "/opt/bundle", "app", NULL};
		char *exec_envp[] = {NULL};
		execve("/usr/bin/crun", exec_argv, exec_envp);
	} else if (pid > 0) {
		int status;
		waitpid(pid, &status, 0);
	} else {
		perror("vfork failed");
	}

	while (1) {
		pause();
	}

	return 0;
}
