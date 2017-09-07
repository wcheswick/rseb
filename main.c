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
int tfd = -1;
int pcap_fd = -1;
int use_syslog = 1;
int is_server;

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


// Construct a sockaddr for either inet or inet6.  if use_ai is true, use the host
// information from addrinfo, else the appropriate version of INADDR_ANY.

struct sockaddr *
make_sa(struct addrinfo *res, int use_ai, socklen_t *sa_length) {
	struct sockaddr *sa;

	*sa_length = res->ai_addrlen;
	sa = (struct sockaddr *)malloc(*sa_length);
	memcpy(sa, res->ai_addr, *sa_length);

	// set local listening address if not use_ai

	switch (sa->sa_family) {
		case AF_INET: {
			struct sockaddr_in *sa4 = (struct sockaddr_in *)sa;
			sa4->sin_addr.s_addr = INADDR_ANY;
//			sa4->sin_port = htons(port);
			break;
		}
		case AF_INET6: {
			struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
			sa6->sin6_addr = in6addr_any;
//			sa6->sin6_port = htons(port);
			break;
		}
	}
	Log(LOG_DEBUG, "make_sa: %s", sa_str(sa));
	return sa;
}

// For the client, this information is derived from the supplied host name/port
// For the server, it is extracted from the incoming connection information
// in the first packet received.

struct sockaddr *remote_tunnel_sa = 0;
socklen_t remote_tunnel_sa_size;

struct addrinfo *tunnel_res = 0;	// XXX this should be remote_tunnel_sa

int
create_udp_tunnel_to_server(char *host_name, char *port_name) {
	int on = 1;
	int s = -1;
	static struct addrinfo hints,  *tunnel_ai;
	int error;
	struct addrinfo *tunnel_local_ai;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	error = getaddrinfo(host_name, port_name, &hints, &tunnel_ai);
	if (error) {
        	Log(LOG_ERR, "getaddress failure:%s", gai_strerror(error));
                return -1;
	}

	for (tunnel_res = tunnel_ai; tunnel_res; tunnel_res = tunnel_res->ai_next) {
		s = socket(tunnel_res->ai_family, tunnel_res->ai_socktype, 
			tunnel_res->ai_protocol);
		if (s >= 0)
			break;
	}
	if (s < 0 || !tunnel_res) {
		Log(LOG_ERR, "tunnel socket failed, %d, %p", s, tunnel_res);
		return -1;
	}
	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
		Log(LOG_ERR, "tunnel setsockopt failed, %s", strerror(errno));
		return -1;
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = tunnel_res->ai_family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_ADDRCONFIG | AI_PASSIVE;
	error = getaddrinfo(NULL, port_name, &hints, &tunnel_local_ai);
	if (error) {
        	Log(LOG_ERR, "getaddress failure for client tunnel source %s",
			gai_strerror(error));
                return -1;
	}
	if (bind(s, (struct sockaddr *)tunnel_local_ai->ai_addr,
		tunnel_local_ai->ai_addrlen) < 0) {
		Log(LOG_ERR, "listener bind to %s failed: %s",
			sa_str((struct sockaddr *)tunnel_local_ai->ai_addr), strerror(errno));
		return -1;
	}
	free(tunnel_local_ai);
	return s;
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
read_tunneled_packet(void) {
	struct sockaddr from_sa;
	socklen_t from_sa_size;
	static u_char buf[1500];
	static packet p;

	p.len = recvfrom(tfd, buf, sizeof(buf), 0, &from_sa, &from_sa_size);
Log(LOG_INFO, "***** %d. %d", p.len, from_sa_size);
	p.data = (const u_char *)&buf;
	if (!remote_tunnel_sa) {
		Log(LOG_INFO, "Client at %s", sa_str(&from_sa));
		remote_tunnel_sa_size = from_sa_size;
		remote_tunnel_sa = (struct sockaddr *)malloc(remote_tunnel_sa_size);
		memcpy(remote_tunnel_sa, &from_sa, remote_tunnel_sa_size);
		Log(LOG_INFO, "client at %s", sa_str(remote_tunnel_sa));
	}

	return &p;
}

void
send_packet_to_remote(packet *pkt) {
	ssize_t n;

	if (is_server && !remote_tunnel_sa) {
		Log(LOG_WARNING, "Tunnel transmission not established yet.");
		return;
	}
	if (tunnel_res)
		n = sendto(tfd, pkt->data, pkt->len, MSG_EOR, 
			(struct sockaddr *)tunnel_res->ai_addr, tunnel_res->ai_addrlen);
	else if (remote_tunnel_sa)
		n = sendto(tfd, pkt->data, pkt->len, MSG_EOR, 
			remote_tunnel_sa, remote_tunnel_sa_size);
	else {
		Log(LOG_WARNING, "huh?");
		n = -1;
	}

	if (n < 0) {
		Log(LOG_WARNING, "packet transmit error %s", strerror(errno));
		return;
	}
	if (n != pkt->len)
		Log(LOG_WARNING, "send_packet_to_remote: short packet: %d %d",
			n, pkt->len);
	if (remote_tunnel_sa)
		Log(LOG_DEBUG, "sent %d bytes to tunnel %s", pkt->len, 
			sa_str(remote_tunnel_sa));
	else
		Log(LOG_DEBUG, "sent %d bytes to tunnel", pkt->len);
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
	char *dev = 0;
	char *port = RSEB_PORT;
	char *remote_host = 0;

	if (getuid() != 0) {
		// because we need access to raw Ethernet packets on a given
		// interface using pcap, both receiving and sending.

		Log(LOG_ERR, "must be run as root");
		fprintf(stderr, "rseb must be run as root\n");
		return 4;
	}

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

	if (is_server) {
		tfd = 0;
	} else {
		tfd = create_udp_tunnel_to_server(remote_host, port);
		if (tfd < 0)
			return 11;
	}

	pcap_fd = init_pcap(dev);
	if (pcap_fd < 0)
		return 12;

	signal(SIGINT, interrupt);
	signal(SIGHUP, interrupt);

	if (is_server) {
		Log(LOG_INFO, "Server bridging interface %s", dev);
	} else {
		Log(LOG_INFO, "Bridging interface %s", dev);
		send_proto(Phello);
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
			if (errno == EINTR)
				break;
			Log(LOG_ERR, "select error: %s, %d, aborting",
				strerror(errno), errno);
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
			pkt = read_tunneled_packet();
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
				case Pheartbeat:
					Log(LOG_INFO, "Lubdub");
					break;
				case Pbye:
					Log(LOG_INFO, "Session terminated by other end");
					return 0;
				default:
					Log(LOG_WARNING, "Unexpected protocol: %d", proto);
				}
			} else {
//				Log(LOG_DEBUG, "packet received, length %d", pkt->len);
			}
			busy = 1;
		}
		if (!busy) {
			send_proto(Pheartbeat);
			Log(LOG_DEBUG, "timeout");
dump_db();
			usleep(500);	// microseconds
		}
	}

	send_proto(Pbye);
	return 0;
}
