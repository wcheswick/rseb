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
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <stdarg.h>
#include <sys/select.h>

#ifdef __FreeBSD__
#include <sys/sockio.h>
#include <sys/limits.h>
#else
#include <linux/sockios.h>
#endif

#include "rseb.h"
#include "arg.h"

#define RSEB_PORT	1127
#define REPORT_INTERVAL	(5*60) // (60*60)	// in seconds

//	debug >= 1	misc debug
//	debug >= 2	all - unconnected - known local - multicast
//	debug >= 3	all - unconnected - known local
//	debug >= 4	all - unconnected
//	debug >= 5	all
//	debug >= 6	all + tunnel reflected

int debug = 0;
int debug_tun_output = 0;
int debug_no_traffic_transmit = 0;

int use_syslog = 1;
int show_arps = 0;

int report_time = 0;
int connected = 0;	// If we have seen at least one protocol packet

int local_packets_sniffed;
int local_bytes_sniffed;
int local_packets_not_needing_tunnel;
int loopback_packets_ignored;
int incoming_tunnel_packets;
int incoming_tunnel_bytes;
int ignored_captured_tunnel_packets;
int ignored_captured_tunnel_bytes;
int unconnected_local_packets;
int unconnected_local_bytes;
int outgoing_tunnel_packets;
int outgoing_tunnel_bytes;
int incoming_proto_packets;
int outgoing_proto_packets;
int local_multicast;
int short_packets;

void
zero_stats(void) {
	local_packets_sniffed = 0;
	local_bytes_sniffed = 0;
	local_packets_not_needing_tunnel = 0;
	loopback_packets_ignored = 0;
	incoming_tunnel_packets = 0;
	incoming_tunnel_bytes = 0;
	ignored_captured_tunnel_packets = 0;
	ignored_captured_tunnel_bytes = 0;
	unconnected_local_packets = 0;
	unconnected_local_bytes = 0;
	outgoing_tunnel_packets = 0;
	outgoing_tunnel_bytes = 0;
	incoming_proto_packets = 0;
	outgoing_proto_packets = 0;
	local_multicast = 0;
	short_packets = 0;
}

int reports = 0;
int not_busy = 0;

int tfd = -1;		// for the tunnel to the remote
int cap_fd = -1;	// local capture fd

int is_server;
sa_family_t family = AF_UNSPEC;	// AF_INET or AF_INET6

#define	SYSLOG_SERVICE	LOG_LOCAL1


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
		        sa_str((struct sockaddr *)tunnel_local_ai->ai_addr),
			strerror(errno));
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
                Log(LOG_ERR, "getaddress failure to '%s', %s", 
		    host_name, gai_strerror(rc));
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
//	Log(LOG_WARNING, "family desired: %d, got %d",
//	    family, tunnel_res->ai_family);
        if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) != 0) {
                Log(LOG_ERR, "tunnel setsockopt failed, %s", strerror(errno));
                return -1;
        }
	if (bind_local_udp(s, port_name) < 0)
		return -1;

	remote_tunnel_sa_size = tunnel_res->ai_addrlen;
	remote_tunnel_sa = (struct sockaddr *)malloc(sizeof(struct sockaddr_storage));
	memcpy(remote_tunnel_sa, tunnel_res->ai_addr, remote_tunnel_sa_size);

	free(tunnel_res);
	return s;
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
//Log(LOG_DEBUG, ">>>TUN %s", pkt_dump_str(pkt));
	n = sendto(tfd, pkt->data, pkt->len, MSG_EOR, 
		remote_tunnel_sa, remote_tunnel_sa_size);
	if (n < 0) {
		Log(LOG_WARNING, "packet transmit error: (%d) %s",
			errno, strerror(errno));
		Log(LOG_WARNING, "tfd=%d len=%d sa=%s",
			tfd, pkt->len, sa_str(remote_tunnel_sa));
exit(13);
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
	if (debug > 1) {
		Log(LOG_WARNING, ">TUN  protocol %s", proto_str(proto_msg));
	}
}

packet *
read_tunneled_packet(int fd) {
	struct sockaddr_storage from_sa;
	socklen_t from_sa_size = sizeof(from_sa);
	static u_char buf[1500];
	static packet p;

	p.len = recvfrom(fd, buf, sizeof(buf), 0, 
		(struct sockaddr *)&from_sa, &from_sa_size);
	p.data = (const u_char *)&buf;
	if (!remote_tunnel_sa) {
		// This is the first connection to this server.  We save
		// the info about the caller so we can continue the
		// conversation.  XX we should comment if someone else
		// butts in

		Log(LOG_INFO, "Tunnel established from (%d) %s",
			from_sa_size, sa_str((struct sockaddr *)&from_sa));
		warned = 0;
		remote_tunnel_sa_size = from_sa_size;
		remote_tunnel_sa = (struct sockaddr *)malloc(sizeof(struct sockaddr_storage));
		memcpy(remote_tunnel_sa, &from_sa, remote_tunnel_sa_size);
	}
	return &p;
}


#ifdef notsimple
int have_tunnel_endpoints = 0;
struct ether_addr tunnel_ether_a;
struct ether_addr tunnel_ether_b;
#endif

int
is_tunnel_traffic(packet *p) {
	struct ether_header *hdr = (struct ether_header *)p->data;
	u_short ether_type;
	int proto;
	struct udphdr *udph;
	uint8_t *protohdr;

#ifdef notsimple
	if (have_tunnel_endpoints) {
		if ((memcmp(&hdr->ether_shost, &tunnel_ether_a, ETHER_ADDR_LEN) &&
		    memcmp(&hdr->ether_dhost, &tunnel_ether_b, ETHER_ADDR_LEN)) ||
		    (memcmp(&hdr->ether_shost, &tunnel_ether_b, ETHER_ADDR_LEN) &&
		    memcmp(&hdr->ether_dhost, &tunnel_ether_a, ETHER_ADDR_LEN)))
			return 1;
	}

	// If this sniffed packet is coming from a host known to be remote,
	// we are probably sniffing a packet we just injected locally.  Ignore it.

	if (show_arps && is_arp(p))
		Log(LOG_INFO, "<LOC arp x3: %s", pkt_dump_str(p));

	if (known_remote_eaddr((struct ether_addr *)&hdr->ether_shost)) {
		if (show_arps && is_arp(p))
			Log(LOG_INFO, "<LOC arp !!! known remote source: %s", pkt_dump_str(p));
		return 1;
	}
#endif
	if (known_remote_eaddr((struct ether_addr *)&hdr->ether_shost)) {
		return 1;
	}

	ether_type = ntohs(hdr->ether_type);
	switch (ether_type) {
	case ETHERTYPE_IP: {
		struct ip *ip = (struct ip *)((u_char *)hdr +
			sizeof(struct ether_header));
		proto = ip->ip_p;
		protohdr = ((u_char *)ip + sizeof(struct ip));
		break;
	}
	case ETHERTYPE_IPV6: {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)((u_char *)hdr + 
			sizeof(struct ether_header));
		proto = ip6->ip6_nxt;
		protohdr = ((u_char *)ip6 + sizeof(*ip6));
		break;
	}
	default:
		return 0;	// can't be a UDP packet
	}

	if (is_arp(p))
		abort();
	if (proto != IPPROTO_UDP)
		return 0;

	udph = (struct udphdr *)protohdr;
	if (ntohs(udph->uh_sport) != RSEB_PORT || 
	    ntohs(udph->uh_dport) != RSEB_PORT)
		return 0;

#ifdef notsimple
	if (!have_tunnel_endpoints) {	// now we do
		char src[ESTRLEN];
		char dst[ESTRLEN];
		
		memcpy(&tunnel_ether_a, &hdr->ether_shost, ETHER_ADDR_LEN);
		memcpy(&tunnel_ether_b, &hdr->ether_dhost, ETHER_ADDR_LEN);
		have_tunnel_endpoints = 1;
	
		ether_print((struct ether_addr *)&hdr->ether_shost, src);
		ether_print((struct ether_addr *)&hdr->ether_dhost, dst);
		Log(LOG_DEBUG, "Have tunnel info: %s / %s  UDP %hu %hu",
			src, dst, ntohs(udph->uh_sport), ntohs(udph->uh_dport));
	}
#endif
	return 1;
}

int
should_forward_local_packet(packet *pkt) {
	// our network tap should not see or process tunnel traffic,
	// That is for our tunnel stuff.  Some configurations have
	// to deliver them.

	if (is_tunnel_traffic(pkt)) {
		ignored_captured_tunnel_packets++;
		ignored_captured_tunnel_bytes += pkt->len;
		if (debug >= 6) {
			Log(LOG_DEBUG, "  tunnel traffic");
		}
		return 0;
	}

	eaddr_is_local((struct ether_addr *)&pkt->ehdr->ether_shost);

	// not connected to a packet tunnel
	if (!connected) {
		unconnected_local_packets++;
		unconnected_local_bytes += pkt->len;
		if (debug >= 5) {
			Log(LOG_DEBUG, "  DNF: not connected");
		}
		return 0;
	}

	// leloo dallas multicast
	if (!IS_EBCAST(pkt->ehdr->ether_dhost) &&
	   IS_EBMCAST(pkt->ehdr->ether_dhost)) {
		local_multicast++;
		if (debug >= 3) {
			Log(LOG_DEBUG, "  DNF: local multicast");
		}
		return 0;	// no multicast, for now
	}

	// local destination
	if (known_local_eaddr((struct ether_addr *)&pkt->ehdr->ether_dhost)) {
		local_packets_not_needing_tunnel++;
		if (debug >= 4) {
			Log(LOG_DEBUG, "  DNF: local dest");
		}
		return 0;
	}

	if (debug >= 3 && IS_EBCAST(pkt->ehdr->ether_dhost)) {
		Log(LOG_DEBUG, "  >TUN  dest is broadcast");
	}
	return 1;
}

void
do_report(void) {
	reports++;
	Log(LOG_NOTICE, "     Tunnel incoming traffic: %d/%d",
		incoming_tunnel_packets, incoming_tunnel_bytes);
	Log(LOG_NOTICE, "               proto packets: %d", incoming_proto_packets);
	Log(LOG_NOTICE, "     Tunnel outgoing traffic: %d/%d",
		outgoing_tunnel_packets, outgoing_tunnel_bytes);
	Log(LOG_NOTICE, "               proto packets: %d", outgoing_proto_packets);
	Log(LOG_NOTICE, "               Local traffic: %d/%d",
		local_packets_sniffed, local_bytes_sniffed);
	if (ignored_captured_tunnel_packets) {
		Log(LOG_NOTICE, "ignored local tunnel traffic: %d/%d",
			ignored_captured_tunnel_packets,
			ignored_captured_tunnel_bytes);
	}
	if (unconnected_local_packets) {
		Log(LOG_NOTICE, "   unconnected local traffic: %d/%d",
			unconnected_local_packets,
			unconnected_local_bytes);
	}

	Log(LOG_NOTICE, "                   ignored: %d", loopback_packets_ignored);
	Log(LOG_NOTICE, "             not forwarded: %d",
		local_packets_not_needing_tunnel);
	if (local_multicast)
		Log(LOG_NOTICE, "           local multicast: %d", local_multicast);
	if (short_packets)
		Log(LOG_NOTICE, "             short packets: %d", short_packets);
	Log(LOG_NOTICE, "          bridge reduction  %.2f %%",
	    100.0*(local_bytes_sniffed - outgoing_tunnel_bytes)/
		(double)local_bytes_sniffed);

	dump_local_eaddrs();
	dump_remote_eaddrs();

	zero_stats();
}

// return 0 if the other end quit

int
do_proto(packet *pkt) {
	int proto = *(int *)pkt->data;

	if (debug >= 4 || debug_tun_output) {
		Log(LOG_DEBUG, "<TUN  proto %s", proto_str(proto));
	}

	switch (proto) {
	case Phello:
		Log(LOG_INFO, "Remote started tunnel session");
		send_proto(Phelloback);
		connected = 1;
		break;
	case Phelloback:
		Log(LOG_INFO, "Remote end is alive");
		connected = 1;
		break;
	case Pheartbeat:
		// Log(LOG_INFO, "Lubdub");
		connected = 1;
		break;
	case Pbye:
		Log(LOG_INFO, "Session terminated by other end");
		do_report();
		send_proto(Pbye);
		return 0;	// time to exit
	default:
		Log(LOG_WARNING, "Unexpected protocol: %d",
			proto);
	}
	return 1;	// keep going
}

void
interrupt(int i) {
	Log(LOG_DEBUG, "interrupt %d, terminating", i);
	send_proto(Pbye);
	do_report();
	exit(1);
}

int
usage(void) {
	fprintf(stderr, "usage: rseb [-A] [-d [-d [-d]]] [-D] [-i interface] [-l] [-p port] [-s] [-4|-6] [-r] [remote server ip [port]]\n");
	return 1;
}

int
main(int argc, char *argv[]) {
	char *dev = 0;
	int port = RSEB_PORT;	// XXXX we assume both end are the same
	char port_name[10];
	char *remote_host = 0;
	int detach = -1;	// default, client detaches, server doesn't
	int lflag = 0;
	time_t next_report = 0;

	if (getuid() != 0) {
		// because we need access to raw Ethernet packets on a given
		// interface.

		Log(LOG_ERR, "must be run as root");
		fprintf(stderr, "rseb must be run as root\n");
		return 4;
	}

	init_db();
	zero_stats();

	ARGBEGIN {
	case 'd':
		debug++;
		break;
	case 'D':
		detach = 0;
		break;
	case 'T':
		debug_tun_output = 1;
		break;
	case 'n':
		debug_no_traffic_transmit = 1;
		break;
	case 'i':
		dev = ARGF();
		break;
	case 'l':
		lflag = 1;	// not inetd, and not detached
		break;
	case 'p':
		port = atoi(ARGF());
		break;
	case 'r':
		report_time = now() + REPORT_INTERVAL;
		break;
	case 's':
		use_syslog = 0;
		break;
	case '4':
		family = AF_INET;
		break;
	case '6':
		family = AF_INET6;
		break;
	case 'A':
		show_arps = 1;
		break;
	default:
		return usage();
	} ARGEND;

	switch (argc) {
	case 0:
		is_server = 1;
		break;
	case 2:			// client, target host and port
		port = atoi(argv[1]);
		// FALLTHROUGH
	case 1:			// client, target host, default port
		remote_host = argv[0];
		is_server = 0;
		break;
	default:
		return usage();
	}

	if (!dev) {
		dev = local_dev();
		if (!dev)
			return 10;
		Log(LOG_DEBUG, "Using local device %s", dev);
	}

	// By default, the client detaches (called at startup) and 
	// server does not (called by inetd)

	if (detach < 0)
		detach = is_server ? 0 : 1;
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

	snprintf(port_name, sizeof(port_name), "%d", port);

	if (use_syslog)
		openlog("rseb", LOG_CONS, SYSLOG_SERVICE);

	if (is_server) {
		if (detach || lflag) {
			if (family == AF_UNSPEC)
				family = AF_INET;
			tfd = create_udp_tunnel_server_listener(port_name);
			if (tfd < 0)
				return 11;
		} else
			tfd = 0;	// stdin, probably from inetd
	} else {
		if (family == AF_UNSPEC) {
			if (strchr(remote_host, ':'))
				family = AF_INET6;
			else
				family = AF_UNSPEC;
		}
		tfd = create_udp_tunnel_to_server(remote_host, port_name);
		if (tfd < 0)
			return 12;
	}

	if (report_time)
		next_report = now() + report_time*60;

	cap_fd = init_capio(dev);
	if (cap_fd < 0)
		return 13;

	signal(SIGINT, interrupt);
	signal(SIGHUP, interrupt);

	if (is_server) {
		Log(LOG_NOTICE, "Server bridging interface %s", dev);
	} else {
		Log(LOG_INFO, "Client bridging interface %s to %s",
		    dev, remote_host);
		send_proto(Phello);
	}

	while (1) {
		int n, busy = 0;
		fd_set fds;
		struct timeval timeout;
		packet *pkt;

		FD_ZERO(&fds);
		FD_SET(cap_fd, &fds);
		FD_SET(tfd, &fds);

		timeout.tv_sec = connected ? 20 : 3;	// seconds CHECKTIME;
		timeout.tv_usec = 0;
		n = select(10, &fds, 0, 0, &timeout);
		if (n < 0) {
			if (errno == EINTR)
				break;
			Log(LOG_ERR, "select error: %s, %d, aborting",
				strerror(errno), errno);
			return 20;
		}

		if (FD_ISSET(cap_fd, &fds)) {	// incoming local packet
			pkt = get_local_packet(cap_fd);
			if (pkt == 0)
				continue;
			local_packets_sniffed++;
			local_bytes_sniffed += pkt->len;
if (debug >= 6) Log(LOG_DEBUG, "LOC %s", pkt_dump_str(pkt));
			if (should_forward_local_packet(pkt)) {
				if (!debug_no_traffic_transmit) {
					outgoing_tunnel_packets++;
					outgoing_tunnel_bytes += pkt->len;
					send_packet_to_remote(pkt);
				}
			}
			busy = 1;
		}
		if (FD_ISSET(tfd, &fds)) {	// remote from the tunnel
			pkt = read_tunneled_packet(tfd);
			if (!pkt)
				continue;
			incoming_tunnel_packets++;
			incoming_tunnel_bytes += pkt->len;

if (debug >= 6) Log(LOG_DEBUG, "TUN %s", pkt_dump_str(pkt));
			if (IS_PROTO(pkt)) {
				incoming_proto_packets++;
				if (!do_proto(pkt))
					return 0;	// He said goodbye
			} else if (!connected) {
				if (debug >= 5 || debug_tun_output) {
					Log(LOG_DEBUG, "LOC<TUN  %s",  pkt_dump_str(pkt));
					Log(LOG_DEBUG, "  not connected, ignored");
				}
			} else {
				if (debug >= 4 || debug_tun_output) {
					Log(LOG_DEBUG, "LOC<TUN  %s",  pkt_dump_str(pkt));
				}
				eaddr_is_remote((struct ether_addr *)&pkt->ehdr->ether_shost);
				put_local_packet(pkt);
			}
			busy = 1;
		}
		if (!busy) {
			if (!connected)
				send_proto(Phello);
			else
				send_proto(Pheartbeat);
			usleep(500);	// microseconds
		}
		if (report_time) {
			time_t t = now();
			if (t > report_time) {
				do_report();
// exit(13);
				report_time = t + REPORT_INTERVAL;
			}
		}
	}

	return 0;
}
