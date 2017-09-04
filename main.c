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
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <sys/select.h>
#include <pcap.h>

#ifdef __FreeBSD__
#include <sys/sockio.h>
#else
#include <linux/sockios.h>
#endif


//#if __FreeBSD_version >= 500000
#include <sys/limits.h>
#include <sys/tree.h>           // for the splay routines
//#else
//#include <machine/limits.h>
//#include "tree.h"               // for the splay routines
//#endif

#include "arg.h"

#define ETHERNET_ADDR_SIZE	6
#define RSEB_PORT	1127

int service_port = RSEB_PORT;
int debug = 0;
int rfd = -1;		// remote tunnel connection
int lfd = -1;		// our local tap/sniff/raw socket


/*
 * I am actually understanding this sockaddr casting crap, finally.  Pascal
 * did this much more cleanly, and safely.
 */

typedef union   sockunion {
        struct  sockaddr sa;
        struct  sockaddr_in sin;
        struct  sockaddr_in6 sin6;
        struct  sockaddr_storage ss; /* added to avoid memory overrun */
} sockunion;

typedef struct ethernet {
	SPLAY_ENTRY(ethernet) next;
	u_char addr[ETHERNET_ADDR_SIZE];
	int incoming, outgoing;
} ethernet;

SPLAY_HEAD(ethernet_tree, ethernet) local_ethernets;

int
ethernet_compare(ethernet *a, ethernet *b) {
	return memcmp((ethernet *)a->addr, (ethernet *)b->addr, ETHERNET_ADDR_SIZE);
}

SPLAY_PROTOTYPE(ethernet_tree, ethernet, next, ethernet_compare);
SPLAY_GENERATE(ethernet_tree, ethernet, next, ethernet_compare);


char *
sutop(sockunion *su) {
	static char buf[500];

	switch (su->sa.sa_family) {
	case PF_INET:
		inet_ntop(PF_INET, &su->sin.sin_addr, buf, sizeof(buf));
		break;
	case PF_INET6:
		inet_ntop(PF_INET6, &su->sin6.sin6_addr, buf, sizeof(buf));
		break;
	default:
		fprintf(stderr, "rseb: sutop, inconceivable family: %d\n",
			su->sa.sa_family);
		abort();
	}
	return buf;
}

/*
 * return a string containing the numeric address in the addrinfo
 */
char *
ai_ntos(struct addrinfo *ai) {
	static char buf[NI_MAXHOST];

	getnameinfo(ai->ai_addr, ai->ai_addrlen, buf, sizeof(buf), 0, 0,
		NI_NUMERICHOST);
	return buf;
}

void
dump_ai(struct addrinfo *ai) {
	fprintf(stderr, "dump_ai	flags=  0x%.08x\n", ai->ai_flags);
	fprintf(stderr, "	family= %d\n", ai->ai_family);
	fprintf(stderr, "	socktyp=%d\n", ai->ai_socktype);
	fprintf(stderr, "	proto=  %d\n", ai->ai_protocol);
	fprintf(stderr, "	addrlen=%d\n", ai->ai_addrlen);
	fprintf(stderr, "	canonnm=%s\n", ai->ai_canonname);
	fprintf(stderr, "	value=  %s\n", ai_ntos(ai));
	if (ai->ai_next)
		dump_ai(ai->ai_next);
}

/*
 * The first parameter is a string containing an IP address.  Crack it and
 * put the results in su.  Return a non-null error string if there is a problem.
 */
char *
crack_ip(const char *buf, sockunion *su, int numeric) {
	struct addrinfo hints, *res;
	static char errbuf[200];
	int error;

	if (debug > 1)
		fprintf(stderr, "crack_ip of %s\n", buf);

	if (buf == 0)
		return "missing: empty string";

	memset(&hints, 0, sizeof(hints));
	if (strchr(buf, ':') != 0)
		hints.ai_family = AF_INET6;
	else
		hints.ai_family = AF_INET;
	if (numeric)
		hints.ai_flags = AI_NUMERICHOST;
	hints.ai_socktype = SOCK_DGRAM;
	error = getaddrinfo(buf, 0, &hints, &res);
	if (error) {
		snprintf(errbuf, sizeof(errbuf), "bad address: %s, %s\n",
			buf, gai_strerror(error));
		return errbuf;
	}
	if (res->ai_next) {
		fprintf(stderr, "crack_ip: too many answers for address %s, ignoring extras:\n", buf);
		dump_ai(res);
	}
	su->sa.sa_family = res->ai_family;
	switch (su->sa.sa_family) {
	case AF_INET:
		su->sin = *((struct sockaddr_in *)res->ai_addr);
		break;
	case AF_INET6:
		su->sin6 = *((struct sockaddr_in6 *)res->ai_addr);
		break;
	default:
		abort();
	}
	freeaddrinfo(res);
	return 0;
}

void
interrupt(int i) {
	if (debug)
		fprintf(stderr,
			"\nrseb interrupt %d, terminating\n", i);
//	finish();
	exit(99);
}

int
usage(void) {
	fprintf(stderr, "usage: rseb [-d] {interface|-} [remote ip [remote port]]\n");
	return 1;
}

int
main(int argc, char *argv[]) {
	int is_server;
	char *tunnel_addr = 0;
	sockunion tunnel_sockaddr;
	char *interface_name;
	char *err = 0;
	char pcap_err_buf[PCAP_ERRBUF_SIZE];
	char *dev;

	SPLAY_INIT(&local_ethernets);

	ARGBEGIN {
	case 'd':
		debug++;
		break;
	default:
		return usage();
	} ARGEND;

	if (argc < 1)	// need an interface name
		return usage();

	switch (argc) {
	case 1:
		is_server = 1;
		break;
	case 3:			// client, target host and port
		service_port = atoi(argv[2]);
		// FALLTHROUGH
	case 2:			// client, target host, default port
		err = crack_ip(argv[1], &tunnel_sockaddr, 0);
		is_server = 0;
		break;
	default:
		return usage();
	}
	interface_name = argv[0];

//	signal(SIGINT, interrupt);
//	signal(SIGHUP, interrupt);

	if (getuid() != 0) {
		// because we need access to raw packets on a given interface,
		// both receiving and sending
		fprintf(stderr, "reb: must be run as root\n");
		exit(2);
	}

	if (strcmp(interface_name, "-") == 0) {
		dev = pcap_lookupdev(pcap_err_buf);
		if (dev == NULL) {
			fprintf(stderr, "rseb: pcap cannot find default device: %s\n",
				pcap_err_buf);
			return 10;
		}
	} else
		dev = interface_name;

	if (debug) {
		if (is_server) {
			fprintf(stderr, "rseb server, interface %s\n",
				dev);
		} else {
			fprintf(stderr, "rseb client, interface %s, remote %s %d \n",
				dev,
				sutop(&tunnel_sockaddr), service_port);
		}
	}

	return 0;
}
