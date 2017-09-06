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

#define RSEB_PORT	"1127"

int debug = 0;
int tfd = -1;		// tunnel connection
int pcap_fd = -1;
int use_syslog = 1;

pcap_t *pcap_handle;
char pcap_err_buf[PCAP_ERRBUF_SIZE];

#define PCAP_FILTER	"arp"



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
create_udp_tunnel_socket(char *host_name, char *port) {
//	int on = 1;
	int s = -1;;
	struct addrinfo hints, *res, *res0;
	int error;
	const char *cause = NULL;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	error = getaddrinfo(host_name, port, &hints, &res0);
	if (error) {
        	Log(LOG_ERR, "getaddress failure:%s", gai_strerror(error));
                return -1;
	}

	for (res = res0; res; res = res->ai_next) {
		s = socket(res->ai_family, res->ai_socktype,
		res->ai_protocol);
		if (s < 0) {
			cause = "socket";
			continue;
		}
#ifdef XXXXX
		if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
			perror("rseb: tunnel setsockopt");
			return -1;
		}
#endif
		if (connect(s, res->ai_addr, res->ai_addrlen) < 0) {
			cause = "connect";
			close(s);
			s = -1;
			continue;
		}

		break;  /* okay we got one */
	}
	if (s < 0) {
		Log(LOG_ERR, "tunnel failed: %s", cause);
		return -1;
	}
	freeaddrinfo(res0);
	return s;
}

// returns NULL if fd is not a socket

char *
get_remote_name(int s) {
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
	ssize_t n = send(tfd, pkt->data, pkt->len, MSG_EOR);
	if (n < 0) {
		Log(LOG_WARNING, "packet transmit error %s", strerror(errno));
		return;
	}
	if (n != pkt->len)
		Log(LOG_WARNING, "send_packet_to_remote: short packet: %d %d",
			n, pkt->len);
	Log(LOG_DEBUG, "sent %d bytes to %s", pkt->len, get_remote_name(tfd));
}

void
send_proto(int proto_msg) {
	packet p;
	p.data = (void *)&proto_msg;
	p.len = sizeof(proto_msg);
	send_packet_to_remote(&p);
}

void
interrupt(int i) {
	Log(LOG_DEBUG, "interrupt %d, terminating", i);
	send_proto(Pbye);
}

int
usage(void) {
	Log(LOG_ERR, "usage: rseb [-d [-d]] [-s] [-i interface] [remote ip [remote port]]");
	return 1;
}

int
main(int argc, char *argv[]) {
	int is_server;
	char *dev = 0;
	char *port = RSEB_PORT;
	char *remote_host = 0;
	char *remote_end;

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
	}

	switch (argc) {
	case 0:
		is_server = 1;
		break;
	case 2:			// client, target host and port
		port = argv[1];
		// FALLTHROUGH
	case 1:			// client, target host, default port
		remote_host = argv[0];
		is_server = 0;
		break;
	default:
		return usage();
	}

	if (getuid() != 0) {
		// because we need access to raw Ethernet packets on a given
		// interface using pcap, both receiving and sending.

		Log(LOG_ERR, "must be run as root");
		return 4;
	}

	// set up tunnel file descriptor

	if (is_server) {	// inetd does the work here
		char *remote_ip = get_remote_name(0);
		if (remote_ip) {
			tfd = 1; // stdout, from inetd
		} else {
			Log(LOG_ERR, "no tunnel connection");
		}
	} else {		// we open a UDP link to our remote selves
		tfd = create_udp_tunnel_socket(remote_host, port);
		if (tfd < 0)
			return 11;
	}

	pcap_fd = init_pcap(dev);
	if (pcap_fd < 0)
		return 12;

	signal(SIGINT, interrupt);
	signal(SIGHUP, interrupt);

	remote_end = get_remote_name(tfd);
	Log(LOG_INFO, "Bridging interface %s to %s", dev, remote_end);

	if (!is_server) {
		send_proto(Phello);
	} else {
Log(LOG_INFO, "server, fd 0 is %s", get_remote_name(0));
Log(LOG_INFO, "server, fd 1 is %s", get_remote_name(1));
	}

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
			if (pkt->len == PROTO_SIZE) {
				int proto = *(int *)pkt->data;
				switch (proto) {
				case Phello:
					Log(LOG_INFO, "Session started at other end");
					send_proto(Phelloback);
					break;
				case Phelloback:
					Log(LOG_INFO, "Remote end is alive");
					break;
				case Pbye:
					Log(LOG_INFO, "Session terminated by other end");
					return 0;
				default:
					Log(LOG_WARNING, "Unexpected protocol: %d", proto);
				}
			} else
				Log(LOG_DEBUG, "packet received, length %d", pkt->len);
			busy = 1;
		}
		if (!busy) {
			Log(LOG_DEBUG, "timeout");
dump_db();
			usleep(500);	// microseconds
		}
	}

	send_proto(Pbye);	// currently not executed
	return 0;
}
