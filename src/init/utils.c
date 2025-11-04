// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "utils.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

int init_socket(uint16_t port) {
	union {
		struct sockaddr_in in;
		struct sockaddr sa;
	} addr;
	int opt = 1;

	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0) {
		return sock;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt) < 0) {
		close(sock);
		return -1;
	}

	memset(&addr, 0, sizeof addr);
	addr.in.sin_family = AF_INET;
	addr.in.sin_port = htons(port);
	addr.in.sin_addr.s_addr = INADDR_ANY;
	if (bind(sock, &addr.sa, sizeof addr) < 0) {
		close(sock);
		return -1;
	}

	if (listen(sock, 5) < 0) {
		close(sock);
		return -1;
	}

	if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
		close(sock);
		return -1;
	}

	return sock;
}

void write_hex(const uint8_t *bytes, ptrdiff_t bytes_len, char *out_hex, ptrdiff_t hex_len) {
	if (bytes_len < 0 || bytes_len > (PTRDIFF_MAX - 1) / 2 || hex_len != bytes_len * 2 + 1) {
		return;
	}

	static const char hexdigits[] = "0123456789abcdef";

	for (ptrdiff_t i = 0; i < bytes_len; i++) {
		out_hex[i * 2] = hexdigits[bytes[i] >> 4U];
		out_hex[i * 2 + 1] = hexdigits[bytes[i] & 0xfU];
	}

	out_hex[hex_len - 1] = '\0';
}

int write_hex_to_file(const char *path, const uint8_t *bytes, ptrdiff_t bytes_len) {
	if (bytes_len < 0 || bytes_len > (PTRDIFF_MAX - 1) / 2) {
		return -1;
	}

	FILE *file = fopen(path, "wb");
	if (!file) {
		return -1;
	}

	ptrdiff_t hex_len = bytes_len * 2 + 1;
	char *hex_str = (char *)malloc((size_t)hex_len);
	if (!hex_str) {
		(void)fclose(file);
		return -2;
	}

	write_hex(bytes, bytes_len, hex_str, hex_len);

	if (fprintf(file, "%s", hex_str) < 0) {
		free(hex_str);
		(void)fclose(file);
		return -1;
	}

	free(hex_str);
	int err = fclose(file);
	if (err) {
		return err;
	}
	return 0;
}

static uint8_t hex_to_lo_nibble(uint8_t chr) {
	if (chr >= '0' && chr <= '9') {
		return chr - '0';
	}
	if (chr >= 'a' && chr <= 'f') {
		return chr - 'a' + 10;
	}
	if (chr >= 'A' && chr <= 'F') {
		return chr - 'A' + 10;
	}
	return 0;
}

static uint8_t hex_to_hi_nibble(uint8_t chr) { return (uint8_t)(hex_to_lo_nibble(chr) << 4U); }

static uint8_t hex_to_byte(const char *str) {
	return hex_to_hi_nibble((uint8_t)str[0]) | hex_to_lo_nibble((uint8_t)str[1]);
}

static bool char_is_hex_digit(uint8_t chr) {
	return (chr >= '0' && chr <= '9') || (chr >= 'a' && chr <= 'f') ||
	       (chr >= 'A' && chr <= 'F');
}

int read_hex(const char *hex, uint8_t *out_bytes, ptrdiff_t bytes_len) {
	if (bytes_len < 0 || bytes_len > PTRDIFF_MAX / 2) {
		return -1;
	}

	ptrdiff_t hex_len = 0;
	while (char_is_hex_digit((uint8_t)hex[hex_len])) {
		if (hex_len == PTRDIFF_MAX) {
			return -1;
		}
		hex_len++;
	}

	if (hex_len != bytes_len * 2) {
		return -1;
	}

	for (ptrdiff_t i = 0; i < bytes_len; i++) {
		out_bytes[i] = hex_to_byte(hex + i * 2);
	}

	return 0;
}

int replace_in_file(const char *path, const char *target, const char *replacement) {
	FILE *file = fopen(path, "r+b");
	if (!file) {
		return -1;
	}

	if (fseek(file, 0, SEEK_END) != 0) {
		(void)fclose(file);
		return -2;
	}
	long lsize = ftell(file);
	if (lsize < 0) {
		(void)fclose(file);
		return -3;
	}
	size_t size = (size_t)lsize;
	if (fseek(file, 0, SEEK_SET) != 0) {
		(void)fclose(file);
		return -4;
	}

	char *data = (char *)malloc(size);
	if (!data) {
		(void)fclose(file);
		return -5;
	}

	if (fread(data, 1, size, file) != size) {
		free(data);
		(void)fclose(file);
		return -6;
	}

	const char *pos = NULL;
	size_t target_len = strlen(target);
	if (target_len > 0 && size >= target_len) {
		for (size_t i = 0; i <= size - target_len; i++) {
			if (data[i] == target[0] && memcmp(data + i, target, target_len) == 0) {
				pos = data + i;
				break;
			}
		}
	}

	if (!pos) {
		free(data);
		(void)fclose(file);
		return -7;
	}

	if (fseek(file, pos - data, SEEK_SET) != 0) {
		free(data);
		(void)fclose(file);
		return -8;
	}
	if (fwrite(replacement, 1, strlen(replacement), file) != strlen(replacement)) {
		free(data);
		(void)fclose(file);
		return -9;
	}

	free(data);
	int err = fclose(file);
	if (err) {
		return -10;
	}
	return 0;
}

int copy_file(const char *src_path, const char *dst_path) {
	int ret = -1;
	FILE *source = NULL;
	FILE *dest = NULL;
	char buf[8192] = {0};
	size_t nread = 0;

	source = fopen(src_path, "rb");
	if (!source) {
		goto cleanup;
	}

	dest = fopen(dst_path, "wb");
	if (!dest) {
		goto cleanup;
	}

	while ((nread = fread(buf, 1, sizeof buf, source)) > 0) {
		if (fwrite(buf, 1, nread, dest) != nread) {
			goto cleanup;
		}
	}

	if (!ferror(source)) {
		ret = 0;
	}

cleanup:
	if (dest) {
		int err = fclose(dest);
		if (err) {
			ret = -1;
		}
	}
	if (source) {
		int err = fclose(source);
		if (err) {
			ret = -1;
		}
	}

	return ret;
}

int zeroize_device(const char *dev_path, uint64_t len) {
	int err = 0;
	int dev_fd = open(dev_path, O_RDWR | O_SYNC);
	{
		if (dev_fd < 0) {
			err = -errno;
			trace("open %s failed: %s\n", dev_path, strerror(errno));
			goto cleanup;
		}

		int flags = fcntl(dev_fd, F_GETFD);
		if (flags >= 0) {
			fcntl(dev_fd, F_SETFD, (uint32_t)flags | FD_CLOEXEC);
		}

		uint64_t range[2] = {0, len};
		if (ioctl(dev_fd, BLKZEROOUT, range) == -1) {
			err = -errno;
			trace("ioctl(BLKZEROOUT) %s failed: %s\n", dev_path, strerror(errno));
			goto cleanup;
		}

		if (fsync(dev_fd) == -1) {
			err = -errno;
			goto cleanup;
		}
	}
cleanup:
	if (dev_fd >= 0) {
		close(dev_fd);
	}
	return err;
}

int snprintf_checked(char *str, ptrdiff_t size, const char *format, ...) {
	va_list args;
	va_start(args, format);
	int actual_size = vsnprintf(str, (size_t)size, format, args);
	va_end(args);

	if (actual_size < 0 || actual_size >= size) {
		return -1;
	}

	return 0;
}
