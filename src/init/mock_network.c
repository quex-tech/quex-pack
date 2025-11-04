// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Quex Technologies
#include "mock_network.h"
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

static const int MOCK_NETWORK_FD = 133385079;
static bool mock_socket_is_open = false;

struct network_data mock_network_incoming = {0};
struct network_data mock_network_outgoing = {0};

ssize_t mock_network_recv(struct network_data *data, void *buf, size_t len) {
	size_t left_len = data->len - data->read_len;
	size_t actual_len = len > left_len ? left_len : len;

	if (actual_len == 0) {
		return 0;
	}

	memcpy(buf, data->buf + data->read_len, actual_len);
	data->read_len += actual_len;

	return (ssize_t)actual_len;
}

ssize_t mock_network_send(struct network_data *data, const void *buf, size_t len) {
	uint8_t *new_buf = (uint8_t *)realloc(data->buf, data->len + len);
	if (!new_buf) {
		return 0;
	}
	data->buf = new_buf;
	memcpy(data->buf + data->len, buf, len);
	data->len += len;

	return (ssize_t)len;
}

void mock_network_reset(struct network_data *data) {
	free(data->buf);
	data->len = 0;
	data->read_len = 0;
}

int __wrap_socket(int domain, int type, int protocol);
int __wrap_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int __wrap_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int __wrap_listen(int sockfd, int backlog);
int __wrap_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int __wrap_close(int sockfd);
ssize_t __wrap_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t __wrap___recv_chk(int sockfd, void *buf, size_t len, size_t buflen, int flags);
ssize_t __wrap_send(int sockfd, const void *buf, size_t len, int flags);

int __real_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
int __real_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
int __real_listen(int sockfd, int backlog);
int __real_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
int __real_close(int sockfd);
ssize_t __real_recv(int sockfd, void *buf, size_t len, int flags);
ssize_t __real_send(int sockfd, const void *buf, size_t len, int flags);

// cppcheck-suppress unusedFunction
int __wrap_socket(int domain, int type, int protocol) {
	(void)domain;
	(void)type;
	(void)protocol;
	mock_socket_is_open = true;
	return MOCK_NETWORK_FD;
}

// cppcheck-suppress unusedFunction
int __wrap_setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen) {
	if (sockfd != MOCK_NETWORK_FD) {
		return __real_setsockopt(sockfd, level, optname, optval, optlen);
	}

	return 0;
}

// cppcheck-suppress unusedFunction
int __wrap_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	if (sockfd != MOCK_NETWORK_FD) {
		return __real_bind(sockfd, addr, addrlen);
	}

	return 0;
}

// cppcheck-suppress unusedFunction
int __wrap_listen(int sockfd, int backlog) {
	if (sockfd != MOCK_NETWORK_FD) {
		return __real_listen(sockfd, backlog);
	}

	return 0;
}

// cppcheck-suppress unusedFunction
int __wrap_accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen) {
	if (sockfd != MOCK_NETWORK_FD) {
		return __real_accept(sockfd, addr, addrlen);
	}

	if (!mock_socket_is_open) {
		errno = EBADF;
		return -1;
	}

	return MOCK_NETWORK_FD;
}

// cppcheck-suppress unusedFunction
int __wrap_close(int sockfd) {
	if (sockfd != MOCK_NETWORK_FD) {
		return __real_close(sockfd);
	}

	mock_socket_is_open = false;
	return 0;
}

ssize_t __wrap_recv(int sockfd, void *buf, size_t len, int flags) {
	if (sockfd != MOCK_NETWORK_FD) {
		return __real_recv(sockfd, buf, len, flags);
	}

	return mock_network_recv(&mock_network_incoming, buf, len);
}

// cppcheck-suppress unusedFunction
ssize_t __wrap___recv_chk(int sockfd, void *buf, size_t len, size_t buflen, int flags) {
	(void)buflen;
	return __wrap_recv(sockfd, buf, len, flags);
}

// cppcheck-suppress unusedFunction
ssize_t __wrap_send(int sockfd, const void *buf, size_t len, int flags) {
	if (sockfd != MOCK_NETWORK_FD) {
		return __real_send(sockfd, buf, len, flags);
	}

	return mock_network_send(&mock_network_outgoing, buf, len);
}
