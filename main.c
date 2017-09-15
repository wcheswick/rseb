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
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <stdarg.h>
#include <sys/select.h>
#include <pcap.h>


#ifdef __FreeBSD__
#include <sys/sockio.h>
#include <sys/limits.h>
#else
#include <linux/sockios.h>
#endif


#include "rseb.h"
#include "arg.h"

#define RSEB_PORT	"1127"
#define REPORT_INTERVAL	(60)	// in minutes

int debug = 0;
int use_syslog = 1;

int report_time = REPORT_INTERVAL;

int local_packets_sniffed = 0;
int local_bytes_sniffed = 0;
int local_packets_not_needing_tunnel = 0;
int loopback_packets_ignored = 0;
int incoming_tunnel_packets = 0;
int incoming_tunnel_bytes = 0;
int outgoing_tunnel_packets = 0;
int outgoing_tunnel_bytes = 0;
int incoming_proto_packets = 0;
int outgoing_proto_packets = 0;
int short_packets = 0;
int empty_packets = 0;

int reports = 0;
int not_busy = 0;

int tfd = -1;		// for the tunnel to the remote
int pcap_fd = -1;	// from the local interface
struct ifreq if_idx;	// for writing to the raw interface

int is_server;
sa_family_t family = AF_UNSPEC;	// AF_INET or AF_INET6

pcap_t *pcap_handle;
char pcap_err_buf[PCAP_ERRBUF_SIZE];

#define PCAP_FILTER	"not ip6 and not udp port 1127"

#define	SYSLOG_SERVICE	LOG_LOCAL1



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
#ifdef notdef
	if (pcap_setdirection(pcap_handle, PCAP_D_IN) < 0) {
		Log(LOG_ERR, "pcap_setdirection failed for '%s': %s", 
			dev, pcap_geterr(pcap_handle));
		return -1;
	}
#endif

	return fd;
}

// bind to the client end of the tunnel to the server.

int
bind_local_udp(int s, char *port_name) {
	struct addrinfo hints;
        struct addrinfo *tunnel_local_ai;
	int rc;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = family;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_protocol = IPPROTO_UDP;
	hints.ai_flags = AI_ADDRCONFIG | AI_PASSIVE;
	rc = getaddrinfo(NULL, port_name, &hints, &tunnel_local_ai);
	if (rc) {
		Log(LOG_ERR, "getaddress failure for client tunnel source %s",
		        gai_strerror(rc));
		return -1;
	}

	if (bind(s, (struct sockaddr *)tunnel_local_ai->ai_addr,
	    tunnel_local_ai->ai_addrlen) < 0) {
		Log(LOG_ERR, "listener bind to %s failed: %s",
		        sa_str((struct sockaddr *)tunnel_local_ai->ai_addr), strerror(errno));
		return -1;
	}
	return 0;
}

struct sockaddr *remote_tunnel_sa = 0;	// filled in when we know we are talking to
socklen_t remote_tunnel_sa_size;

int
create_udp_tunnel_server_listener(char *port_name) {
	int on = 1;
	int s = -1;

	s = socket(family, SOCK_DGRAM, IPPROTO_UDP);
	if (s < 0) {
        	Log(LOG_ERR, "socket failure: %s", strerror(errno));
                return -1;
	}

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
	    (char *)&on, sizeof(on)) != 0) {
		perror("portinit setsockopt");
		exit(13);
	}

	if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
		Log(LOG_ERR, "tunnel setsockopt failed, %s", strerror(errno));
		return -1;
	}
	if (bind_local_udp(s, port_name) < 0) {
		return -1;
	}

	Log(LOG_DEBUG, "listener started");
	return s;
}

// For the client, this information is derived from the supplied host name/port
// For the server, it is extracted from the incoming connection information
// in the first packet received.


int
create_udp_tunnel_to_server(char *host_name, char *port_name) {
        int on = 1;
        int s = -1;
	struct addrinfo hints;
	int rc;
        struct addrinfo *tunnel_ai, *tunnel_res;

        memset(&hints, 0, sizeof(hints));
        hints.ai_family = family;
        hints.ai_socktype = SOCK_DGRAM;
        hints.ai_protocol = IPPROTO_UDP;
        rc = getaddrinfo(host_name, port_name, &hints, &tunnel_ai);
        if (rc) {
                Log(LOG_ERR, "getaddress failure:%s", gai_strerror(rc));
                return -1;
        }

        for (tunnel_res = tunnel_ai; tunnel_res; tunnel_res = tunnel_res->ai_next) {
                s = socket(tunnel_res->ai_family, tunnel_res->ai_socktype, 
                        tunnel_res->ai_protocol);
                if (s >= 0)
                        break;
        }
        if (s < 0) {
                Log(LOG_ERR, "tunnel socket failed, %d, %p", s, tunnel_res);
                return -1;
        }
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
                Log(LOG_ERR, "tunnel setsockopt failed, %s", strerror(errno));
                return -1;
        }
	if (bind_local_udp(s, port_name) < 0)
		return -1;

	remote_tunnel_sa_size = tunnel_res->ai_addrlen;
	remote_tunnel_sa = (struct sockaddr *)malloc(remote_tunnel_sa_size);
	memcpy(remote_tunnel_sa, tunnel_res->ai_addr, remote_tunnel_sa_size);

	free(tunnel_res);
	return s;
}

int
unwanted_packet(packet *p) {
	struct ether_header *ehdr;
	if (!p)
		return 1;

	ehdr = (struct ether_header *)p->data;
	switch (ntohs(ehdr->ether_type)) {
	case ETHERTYPE_ARP:
		return 0;
	case ETHERTYPE_IP:
		return 0;
	case ETHERTYPE_IPV6:
abort();
		return 1;
	default:
		return 1;
	}
	return 1;
}

packet *
get_local_packet(void) {
	struct pcap_pkthdr *phdr;
	static packet p;
	int rc = pcap_next_ex(pcap_handle, &phdr, &p.data);
	switch (rc) {
	case 0:		// timeout
		Log(LOG_DEBUG, "pcap timeout");
		return 0;
	case 1:		// have a packet
		break;
	default:	// some error
		Log(LOG_WARNING, "pcap_next_ex error (%d): %s", 
			rc, pcap_geterr(pcap_handle));
		return 0;
	}

	if (phdr->len == 0) {
		empty_packets++;
		return 0;
	}
	p.len = phdr->caplen;
	return &p;
}

int warned = 0;

void
send_packet_to_remote(packet *pkt) {
	ssize_t n;

	if (is_server && !remote_tunnel_sa) {
		if (!warned) {
			Log(LOG_INFO, "Awaiting first incoming tunnel packet");
			warned = 1;
		}
		return;
	}
	n = sendto(tfd, pkt->data, pkt->len, MSG_EOR, 
		remote_tunnel_sa, remote_tunnel_sa_size);
	if (n < 0) {
		Log(LOG_WARNING, "packet transmit error %s", strerror(errno));
		return;
	}
	if (n != pkt->len)
		Log(LOG_WARNING, "send_packet_to_remote: short packet: %d %d",
			n, pkt->len);
}

void
send_proto(int proto_msg) {
	packet p;
	outgoing_proto_packets++;
	p.data = (void *)&proto_msg;
	p.len = sizeof(proto_msg);
	send_packet_to_remote(&p);
}

packet *
read_tunneled_packet(void) {
	struct sockaddr from_sa;
	socklen_t from_sa_size = sizeof(from_sa);
	static u_char buf[1500];
	static packet p;

	p.len = recvfrom(tfd, buf, sizeof(buf), 0, &from_sa, &from_sa_size);
	p.data = (const u_char *)&buf;
	if (!remote_tunnel_sa) {
		// This is the first connection to this server.  We save
		// the info about the caller so we can continue the
		// conversation.  XX we should comment if someone else
		// butts in

		Log(LOG_INFO, "Tunnel established from %s", sa_str(&from_sa));
		warned = 0;
		remote_tunnel_sa_size = from_sa_size;
		remote_tunnel_sa = (struct sockaddr *)malloc(remote_tunnel_sa_size);
		memcpy(remote_tunnel_sa, &from_sa, remote_tunnel_sa_size);

		// we should not forward any traffic through the tunnel that
		// has the remote ethernet in it.  I think.
		// XXX what about at the client?

		add_local_eaddr(ETHER(&p)->ether_shost);
	}
	return &p;
}

void
inject_packet_from_remote(packet *pkt) {
	int n;

	n = pcap_sendpacket(pcap_handle, pkt->data, pkt->len);
	if (n < 0) {
		Log(LOG_WARNING, "pcap raw write error: %s",
			pcap_geterr(pcap_handle));
	}
}

void
do_report(void) {
	reports++;
	Log(LOG_NOTICE, "   Tunnel incoming packets: %d", incoming_tunnel_packets);
	Log(LOG_NOTICE, "                     bytes: %d", incoming_tunnel_bytes);
	Log(LOG_NOTICE, "             proto packets: %d", incoming_proto_packets);
	Log(LOG_NOTICE, "   Tunnel outgoing packets: %d", outgoing_tunnel_packets);
	Log(LOG_NOTICE, "                     bytes: %d", outgoing_tunnel_bytes);
	Log(LOG_NOTICE, "             proto packets: %d", outgoing_proto_packets);
	Log(LOG_NOTICE, "     Local packets sniffed: %d", local_packets_sniffed);
	Log(LOG_NOTICE, "                   ignored: %d", loopback_packets_ignored);
	Log(LOG_NOTICE, "             not forwarded: %d", local_packets_not_needing_tunnel);
	Log(LOG_NOTICE, "             short packets: %d", short_packets);
	Log(LOG_NOTICE, "             empty packets: %d", empty_packets);
	Log(LOG_NOTICE, "             bytes sniffed: %d", local_bytes_sniffed);
	Log(LOG_NOTICE, "       bytes not forwarded: %d",
	    local_bytes_sniffed - outgoing_tunnel_bytes);
	Log(LOG_NOTICE, "          bridge reduction  %.2f %%",
	    100.0*(local_bytes_sniffed - outgoing_tunnel_bytes)/(double)local_bytes_sniffed);

	incoming_tunnel_packets = 0;
	incoming_tunnel_bytes = 0;
	incoming_proto_packets = 0;
	outgoing_tunnel_packets = 0;
	outgoing_tunnel_bytes = 0;
	outgoing_proto_packets = 0;
	local_packets_sniffed = 0;
	local_bytes_sniffed = 0;
	loopback_packets_ignored = 0;
	local_packets_not_needing_tunnel = 0;
	short_packets = 0;

	Log(LOG_INFO, "Local Ethernet address cache:");
	dump_local_eaddrs();
	Log(LOG_INFO, "Remote Ethernet address cache:");
	dump_remote_eaddrs();
	Log(LOG_INFO, "Reports generated: %d", reports);
}

void
interrupt(int i) {
	Log(LOG_DEBUG, "interrupt %d, terminating", i);
	send_proto(Pbye);
}

int
usage(void) {
	fprintf(stderr, "usage: rseb [-d [-d]] [-D] [-e] [-i interface] [-p port] [-r minutes] [remote server ip]");
	return 1;
}

int
main(int argc, char *argv[]) {
	char *dev = 0;
	char *port = RSEB_PORT;
	char *remote_host = 0;
	int detach = 0;
	int lflag = 0;
	time_t next_report = 0;

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
	case 'D':
		detach = 1;
		break;
	case 'i':
		dev = ARGF();
		break;
	case 'l':
		lflag = 1;	// not inetd, and not detached
		break;
	case 'p':
		port = ARGF();
		break;
	case 'r':
		report_time = atoi(ARGF());
		break;
	case 'e':
		use_syslog = 0;
		break;
	case '4':
		family = AF_INET;
		break;
	case '6':
		family = AF_INET6;
		break;
	default:
		return usage();
	} ARGEND;

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

	if (!dev) {
		dev = pcap_lookupdev(pcap_err_buf);
		if (dev == NULL) {
			Log(LOG_ERR, "pcap cannot find default device: %s",
				pcap_err_buf);
			return 10;
		}
	}

	if (detach) {
		use_syslog = 1;
		switch (fork()) {
		case -1:
			perror("detaching");
			exit(1);
		case 0:
			setsid();
			break;
		default:
			exit(0);
		}
	}
	if (use_syslog)
		openlog("rseb", LOG_CONS, SYSLOG_SERVICE);

	if (is_server) {
		if (detach || lflag) {
			if (family == AF_UNSPEC)
				family = AF_INET;
			tfd = create_udp_tunnel_server_listener(port);
			if (tfd < 0)
				return 11;
		} else
			tfd = 0;	// stdin, probably from inetd
	} else {
		if (family == AF_UNSPEC) {
			if (strchr(remote_host, ':'))
				family = AF_INET6;
			else
				family = AF_INET;
		}
		tfd = create_udp_tunnel_to_server(remote_host, port);
		if (tfd < 0)
			return 12;
	}

	if (report_time)
		next_report = now() + report_time*60;

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
			return 20;
		}

		if (FD_ISSET(pcap_fd, &fds)) {		// incoming local packet
			pkt = get_local_packet();
			if (unwanted_packet(pkt))
				continue;
			Log(LOG_DEBUG, "local:    %s", pkt_str(pkt));
			local_packets_sniffed++;
			local_bytes_sniffed += pkt->len;
			// see if we are sniffing our own bridged traffic
			if (known_remote_eaddr(ETHER(pkt)->ether_shost)) {
				loopback_packets_ignored++;
				Log(LOG_DEBUG, "local:    %s loopback", pkt_str(pkt));
				continue;
			}

			// if destination is known to be local, don't forward
			if (known_local_eaddr(ETHER(pkt)->ether_dhost)) {
				local_packets_not_needing_tunnel++;
				Log(LOG_DEBUG, "local:    %s opt", pkt_str(pkt));
				continue;
			}
			add_local_eaddr(ETHER(pkt)->ether_shost); // remember local src
//			if (IS_EBCAST(ETHER(pkt)->ether_dhost)) {
				outgoing_tunnel_packets++;
				outgoing_tunnel_bytes += pkt->len;
				Log(LOG_INFO, " >tunnel: %s", tunnel_str(pkt));
				send_packet_to_remote(pkt);
//			}
			busy = 1;
		}
		if (FD_ISSET(tfd, &fds)) { 	// remote from the tunnel
			pkt = read_tunneled_packet();
			if (!pkt)
				continue;
			incoming_tunnel_packets++;
			incoming_tunnel_bytes += pkt->len;
			Log(LOG_INFO, " <tunnel: %s", tunnel_str(pkt));
			if (IS_PROTO(pkt)) {
				incoming_proto_packets++;
				int proto = PROTO(pkt);
				switch (proto) {
				case Phello:
					Log(LOG_INFO, "Remote started tunnel session");
					send_proto(Phelloback);
					break;
				case Phelloback:
					Log(LOG_INFO, "Remote end is alive");
					break;
				case Pheartbeat:
					// Log(LOG_INFO, "Lubdub");
					break;
				case Pbye:
					Log(LOG_INFO, "Session terminated by other end");
					return 0;
				default:
					Log(LOG_WARNING, "Unexpected protocol: %d",
						proto);
				}
			} else {
				add_remote_eaddr(ETHER(pkt)->ether_shost);
				inject_packet_from_remote(pkt);
			}
			busy = 1;
		}
		if (report_time && now() >= next_report) {
			do_report();
			next_report = now() + report_time*60;
		}
		if (!busy) {
			not_busy++;
			send_proto(Pheartbeat);
			Log(LOG_DEBUG, "timeout");
			usleep(500);	// microseconds
		}
	}

	send_proto(Pbye);
	return 0;
}
