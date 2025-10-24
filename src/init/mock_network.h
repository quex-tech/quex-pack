#ifndef MOCK_NETWORK_H
#define MOCK_NETWORK_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct network_data {
	uint8_t *buf;
	size_t len;
	size_t read_len;
};

extern struct network_data mock_network_incoming;
extern struct network_data mock_network_outgoing;

ssize_t mock_network_recv(struct network_data *data, void *buf, size_t len);
ssize_t mock_network_send(struct network_data *data, const void *buf, size_t len);
void mock_network_reset(struct network_data *data);

#endif
