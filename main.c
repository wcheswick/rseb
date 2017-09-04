#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <assert.h>

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <sys/sockio.h>
#include <sys/un.h>
#include <sys/select.h>

#if __FreeBSD_version >= 500000
#include <sys/limits.h>
#include <sys/tree.h>           // for the splay routines
#else
#include <machine/limits.h>
#include "tree.h"               // for the splay routines
#endif

#include "arg.h"

#define ETHERNET_ADDR_SIZE	6
#define RSEB_PORT	1127

char *service_port = RSEB_PORT;
int debug = 0;
int rfd = -1;		// remote tunnel connection
int lfd = -1;		// our local tap/sniff/raw socket


typedef struct ethernet {
	SPLAY_ENTRY(session) next;
	u_char addr[ETHERNET_ADDR_SIZE];
	int incoming, outgoing;
} ethernet;

SPLAY_HEAD(ethernet_tree, local_ethernet) local_ethernets;

SPLAY_PROTOTYPE(ethernet_tree, ethernet, next, ethernet_compare);
SPLAY_GENERATE(ethernet_tree, ethernet, next, ethernet_compare);

int
ethernet_compare(ethernet *a, ethernet *b) {
	return memcmp(a->addr, b->addr, ETHERNET_ADDR_SIZE);
}

int
usage(void) {
	fprintf(stderr, "usage: rseb interface [remote ip [remote port]]\n");
	return 1;
}

int
main(int arc, char *argv[]) {
	return 0;
}
