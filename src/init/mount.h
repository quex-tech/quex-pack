#ifndef _MOUNT_H_
#define _MOUNT_H_

struct mount_spec {
	const char *source;
	const char *target;
	const char *fstype;
	unsigned long flags;
};

int parse_mount_spec(char *input, struct mount_spec *output);

#endif