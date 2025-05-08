#include <arpa/inet.h>
#include <signal.h>
#include <stdio.h>
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
