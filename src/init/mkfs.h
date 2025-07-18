#ifndef _MKFS_H_
#define _MKFS_H_

struct mkfs_spec {
	const char *dev;
	const char *fstype;
	const char *options;
};

int parse_mkfs_spec(char *input, struct mkfs_spec *output);
int mkfs(struct mkfs_spec *spec);

#endif