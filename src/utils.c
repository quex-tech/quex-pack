#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int load_binary(const char *path, void *out, size_t size) {
	FILE *fp = fopen(path, "rb");
	if (!fp) {
		return -1;
	}

	if (fread(out, 1, size, fp) != size) {
		fclose(fp);
		return -1;
	}

	fclose(fp);
	return 0;
}

int init_socket(uint16_t port) {
	union {
		struct sockaddr_in in;
		struct sockaddr sa;
	} addr;
	int opt = 1;

	int sock;
	if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		return sock;
	}

	if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.in.sin_family = AF_INET;
	addr.in.sin_port = htons(port);
	addr.in.sin_addr.s_addr = INADDR_ANY;
	if (bind(sock, &addr.sa, sizeof(addr)) < 0) {
		close(sock);
		return -1;
	}

	if (listen(sock, 5) < 0) {
		close(sock);
		return -1;
	}

	signal(SIGPIPE, SIG_IGN);
	return sock;
}

void write_hex(uint8_t *bytes, size_t bytes_len, char *dest) {
	for (size_t i = 0; i < bytes_len; i++) {
		snprintf(dest + i * 2, 3, "%02x", bytes[i]);
	}
}

int replace_in_file(const char *filename, const char *target, const char *replacement) {
	FILE *f = fopen(filename, "r+b");
	if (!f) {
		return -1;
	}

	fseek(f, 0, SEEK_END);
	long lsize = ftell(f);
	if (lsize < 0) {
		fclose(f);
		return -2;
	}
	size_t size = (size_t)lsize;
	rewind(f);

	char *data = malloc(size);
	if (!data) {
		fclose(f);
		return -3;
	}

	if (fread(data, 1, size, f) != size) {
		free(data);
		fclose(f);
		return -4;
	}

	char *pos = memmem(data, size, target, strlen(target));
	if (!pos) {
		free(data);
		fclose(f);
		return -5;
	}

	fseek(f, pos - data, SEEK_SET);
	fwrite(replacement, 1, strlen(replacement), f);

	free(data);
	fclose(f);
	return 0;
}
