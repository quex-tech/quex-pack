#include "key.h"
#include <sys/mount.h>
#include <unistd.h>

int main(void) {
	mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
	mount("none", "/proc", "proc", 0, NULL);
	mount("none", "/sys", "sysfs", 0, NULL);
	mount("none", "/sys/kernel/config", "configfs", 0, NULL);

	uint8_t sk[32];
	if (get_sk(sk) != 0) {
		// exit(EXIT_FAILURE);
	}

	while (1) {
		pause();
	}

	return 0;
}
