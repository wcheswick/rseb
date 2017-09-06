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
#include <stdarg.h>
#include <sys/select.h>
#include <pcap.h>
#include <net/ethernet.h>

#ifdef __FreeBSD__
#include <sys/sockio.h>
#include <sys/limits.h>
#else
#include <linux/sockios.h>
#endif


#include "rseb.h"
#include "arg.h"

#define RSEB_PORT	1127

int service_port = RSEB_PORT;
int debug = 0;
int tfd = -1;		// tunnel connection
int pcap_fd = -1;
int use_syslog = 1;

pcap_t *pcap_handle;
char pcap_err_buf[PCAP_ERRBUF_SIZE];

#define PCAP_FILTER	"arp"

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

sockunion tunnel_sockaddr;


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
		Log(LOG_ERR, "sutop, inconceivable family: %d\n",
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
	Log(LOG_DEBUG, "dump_ai	flags=  0x%.08x\n", ai->ai_flags);
	Log(LOG_DEBUG, "	family= %d\n", ai->ai_family);
	Log(LOG_DEBUG, "	socktyp=%d\n", ai->ai_socktype);
	Log(LOG_DEBUG, "	proto=  %d\n", ai->ai_protocol);
	Log(LOG_DEBUG, "	addrlen=%d\n", ai->ai_addrlen);
	Log(LOG_DEBUG, "	canonnm=%s\n", ai->ai_canonname);
	Log(LOG_DEBUG, "	value=  %s\n", ai_ntos(ai));
	if (ai->ai_next)
		dump_ai(ai->ai_next);
}

// return an fd for the pcap device if all is ok

int
init_pcap(char *dev) {
	struct bpf_program fp;
	int fd;

	pcap_handle = pcap_open_live(dev, BUFSIZ, 1, 1, pcap_err_buf);
	if (pcap_handle == NULL) {
		Log(LOG_ERR, "could not open interface '%s': %s",
			dev, pcap_err_buf);
		return -1;
	}
	if (pcap_setnonblock(pcap_handle, 1, pcap_err_buf) < 0) {
		Log(LOG_ERR, "ipcap_setnonblock failed: %s", pcap_err_buf);
		return -1;
	}
	if (pcap_datalink(pcap_handle) != DLT_EN10MB) {
		Log(LOG_ERR, "interface '%s' not supported", dev);
		return -1;
	}

	if (pcap_compile(pcap_handle, &fp, PCAP_FILTER, 0, 0) < 0) {
		Log(LOG_ERR, "bad filter: '%s', %s", 
			PCAP_FILTER, pcap_geterr(pcap_handle));
		return -1;
	}
	if (pcap_setfilter(pcap_handle, &fp) < 0) {
		Log(LOG_ERR, "could not install filter: '%s', %s", 
			PCAP_FILTER, pcap_geterr(pcap_handle));
		return -1;
	}

	fd = pcap_get_selectable_fd(pcap_handle);
	if (fd < 0) {
		Log(LOG_ERR, "pcap device unsuitable for select '%s'", 
			dev);
		return -1;
	}

	return fd;
}

int
udp_tunnel_socket(sockunion *sa, int port) {
	int on = 1;
	struct sockaddr tunaddr;
	int s;

	memset(&tunaddr, 0, sizeof(tunaddr));
	switch (sa->sa.sa_family) {
		case AF_INET: {
			struct sockaddr_in *sin = (struct sockaddr_in *)&tunaddr;
			sin->sin_family = sa->sa.sa_family;
			sin->sin_port = htons(port);	// any source port in a storm
			sin->sin_addr.s_addr = INADDR_ANY;
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&tunaddr;
			sin6->sin6_family = sa->sa.sa_family;
			sin6->sin6_port = htons(port);	// any source port in a storm
			sin6->sin6_flowinfo = 0;	// why?
			sin6->sin6_addr = in6addr_any;
			break;
		}
	}

	s = socket(sa->sa.sa_family, SOCK_DGRAM, 0);
	if (s < 0) {
		perror("rseb: udp socket");
		return -1;
	}

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
		perror("rseb: tunnel setsockopt");
		return -1;
	}

	return s;
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

	Log(LOG_DEBUG, "crack_ip of %s", buf);

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
		Log(LOG_ERR, "crack_ip: too many answers for address %s, ignoring extras:", buf);
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

// returns NULL if fd is not a socket

char *
getcaller(int s) {
	socklen_t len;
	struct sockaddr_storage addr;
	static char ipstr[INET6_ADDRSTRLEN];
	int port = 0;
	
	len = sizeof addr;
	if (getpeername(s, (struct sockaddr*)&addr, &len) < 0) {
		switch (errno) {
		case ENOTSOCK:
			return NULL;
		default:
			return strerror(errno);
		}
	}
	
	if (addr.ss_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *)&addr;
		port = ntohs(s->sin_port);
		inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr);
	} else if (addr.ss_family == AF_INET6) {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)&addr;
		port = ntohs(s->sin6_port);
		inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr);
	} else {
		snprintf(ipstr, sizeof(ipstr), "(unknown address family %d)",
			addr.ss_family);
	}
	Log(LOG_DEBUG, "remote: %s: %d", ipstr, port);
	return ipstr;
}

packet *
get_local_packet(void) {
	struct pcap_pkthdr *phdr;
	static packet p;
	struct ether_header *ehdr;
	int rc = pcap_next_ex(pcap_handle, &phdr, &p.data);
	switch (rc) {
	case 0:		// timeout
		Log(LOG_DEBUG, "pcap timeout");
		return 0;
	case 1:		// have a packet
		break;
	default:	// some error
		Log(LOG_WARNING, "pcap_next_ex error: %s", pcap_geterr(pcap_handle));
		return 0;
	}

	ehdr = (struct ether_header *)p.data;
	Log(LOG_DEBUG, "  local: %s", edump(ehdr));
	if (phdr->caplen != phdr->len) {
		Log(LOG_WARNING, "short packet, %d != %d", phdr->caplen != phdr->len);
	}
	p.len = phdr->caplen;
	return &p;
}

packet *
get_remote_packet(void) {
	static u_char buf[1500];
	struct sockaddr sa;
	socklen_t sa_len = sizeof(sa);
	static packet p;
	p.len = recvfrom(tfd, buf, sizeof(buf), 0, &sa, &sa_len);
	p.data = (const u_char *)&buf;
	return &p;
}

void
send_packet_to_remote(packet *pkt) {
	socklen_t to_len = sizeof(tunnel_sockaddr);
	ssize_t n = sendto(tfd, pkt->data, pkt->len, 0, &tunnel_sockaddr, to_len);
	if (n < 0) {
		Log(LOG_WARNING, "packet transmit error %s", strerror(errno));
		return;
	}
	if (n != pkt->len)
		Log(LOG_WARNING, "send_packet_to_remote: short packet: %d %d",
			n, pkt->len);
	Log(LOG_DEBUG, "sending %d bytes", pkt->len);
}

void
interrupt(int i) {
	Log(LOG_DEBUG, "interrupt %d, terminating", i);
//	finish();
}

int
usage(void) {
	Log(LOG_ERR, "usage: rseb [-d [-d]] [-s] [-i interface] [remote ip [remote port]]");
	return 1;
}

int
main(int argc, char *argv[]) {
	int is_server;
	char *err = 0;
	char *dev = 0;

	init_db();

	ARGBEGIN {
	case 'd':
		debug++;
		break;
	case 'i':
		dev = ARGF();
		break;
	case 's':
		use_syslog = 0;		// stderr instead
		break;
	default:
		return usage();
	} ARGEND;

	if (use_syslog)
		openlog("rseb", LOG_CONS, LOG_DAEMON);

	if (!dev) {
		dev = pcap_lookupdev(pcap_err_buf);
		if (dev == NULL) {
			Log(LOG_ERR, "pcap cannot find default device: %s",
				pcap_err_buf);
			return 10;
		}
		Log(LOG_INFO, "Bridging local interface %s", dev);
	}

	switch (argc) {
	case 0:
		is_server = 1;
		break;
	case 2:			// client, target host and port
		service_port = atoi(argv[1]);
		if (service_port < 1 || service_port > IPPORT_MAX) {
			Log(LOG_ERR, "bad port number: %s", argv[2]);
			return 2;
		}
		// FALLTHROUGH
	case 1:			// client, target host, default port
		err = crack_ip(argv[0], &tunnel_sockaddr, 0);
		is_server = 0;
		break;
	default:
		return usage();
	}
	if (err) {
		Log(LOG_ERR, "%s: %s", argv[0], err);
		return 3;
	}

	if (getuid() != 0) {
		// because we need access to raw Ethernet packets on a given
		// interface using pcap, both receiving and sending.

		Log(LOG_ERR, "must be run as root");
		return 4;
	}

	if (is_server) {
		Log(LOG_DEBUG, "rseb server, interface %s", dev);
	} else {
		Log(LOG_DEBUG, "rseb client, interface %s, remote %s %d",
			dev, sutop(&tunnel_sockaddr), service_port);
	}

	// set up tunnel file descriptor

	if (is_server) {	// inetd does the work here
		char *remote_ip = getcaller(0);
		if (remote_ip) {
			tfd = 0; // stdin, from inetd
			Log(LOG_DEBUG, "remote is %s", remote_ip);
		} else {
			Log(LOG_ERR, "no tunnel connection");
// XXXXX			return 10;
		}
	} else {		// we open a UDP link to our remote selves
		tfd = udp_tunnel_socket(&tunnel_sockaddr, RSEB_PORT);
		if (tfd < 0)
			return 11;
	}

	pcap_fd = init_pcap(dev);
	if (pcap_fd < 0)
		return 12;

//	signal(SIGINT, interrupt);
//	signal(SIGHUP, interrupt);

	Log(LOG_DEBUG, "Running....");

	while (1) {
		int n, busy = 0;
		fd_set fds;
		struct timeval timeout;
		packet *pkt;

		FD_ZERO(&fds);
		FD_SET(pcap_fd, &fds);
		FD_SET(tfd, &fds);

		timeout.tv_sec = 10;	// seconds CHECKTIME;
		timeout.tv_usec = 0;
		n = select(10, &fds, 0, 0, &timeout);
		if (n < 0) {
			Log(LOG_ERR, "select error: %s, %d, aborting",
				strerror(errno), n);
			return 20;;
		}

		if (FD_ISSET(pcap_fd, &fds)) {		// incoming local packet
			pkt = get_local_packet();
			if (!pkt)
				continue;
			add_entry(ETHER(pkt)->ether_shost);
			if (IS_EBCAST(ETHER(pkt)->ether_dhost) ||
			    !known_entry(ETHER(pkt)->ether_dhost)) {
				send_packet_to_remote(pkt);
			}
			busy = 1;
		}
		if (FD_ISSET(tfd, &fds)) { 	// something from the tunnel
			pkt = get_remote_packet();
			if (!pkt)
				continue;
			busy = 1;
		}
		if (!busy) {
			Log(LOG_DEBUG, "timeout");
dump_db();
			usleep(500);	// microseconds
		}
	}

	return 0;
}
