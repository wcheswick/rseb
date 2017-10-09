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

#define RSEB_PORT	"1127"
#define REPORT_INTERVAL	10	// (60*60)	// in seconds


//	debug > 2	show all packet decisions
//	debug > 1	show packet decisions not involving known local traffic
//	debug == 1	misc debug

int debug = 0;
int use_syslog = 1;

int report_time = 0;
int connected = 0;	// If we have seen at least one protocol packet

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
read_tunneled_packet(void) {
	struct sockaddr_storage from_sa;
	socklen_t from_sa_size = sizeof(from_sa);
	static u_char buf[1500];
	static packet p;


	p.len = recvfrom(tfd, buf, sizeof(buf), 0, 
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

void
do_report(void) {
	reports++;
	Log(LOG_NOTICE, "   Tunnel incoming traffic: %d/%d",
		incoming_tunnel_packets, incoming_tunnel_bytes);
	Log(LOG_NOTICE, "             proto packets: %d", incoming_proto_packets);
	Log(LOG_NOTICE, "   Tunnel outgoing traffic: %d/%d",
		outgoing_tunnel_packets, outgoing_tunnel_bytes);
	Log(LOG_NOTICE, "             proto packets: %d", outgoing_proto_packets);
	Log(LOG_NOTICE, "             Local traffic: %d/%d",
		local_packets_sniffed, local_bytes_sniffed);
	Log(LOG_NOTICE, "                   ignored: %d", loopback_packets_ignored);
	Log(LOG_NOTICE, "             not forwarded: %d",
		local_packets_not_needing_tunnel);
	if (short_packets)
		Log(LOG_NOTICE, "             short packets: %d", short_packets);
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

	dump_local_eaddrs();
	dump_remote_eaddrs();
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
	fprintf(stderr, "usage: rseb [-d [-d [-d]]] [-D] [-i interface] [-l] [-p port] [-s] [-4|-6] [-r] [remote server ip]\n");
	return 1;
}

int
main(int argc, char *argv[]) {
	char *dev = 0;
	char *port = RSEB_PORT;
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

	ARGBEGIN {
	case 'd':
		debug++;
		break;
	case 'D':
		detach = 0;
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
				family = AF_UNSPEC;
		}
		tfd = create_udp_tunnel_to_server(remote_host, port);
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

		if (FD_ISSET(cap_fd, &fds)) {		// incoming local packet
			pkt = get_local_packet();
			local_packets_sniffed++;
			local_bytes_sniffed += pkt->len;

			if (!connected) {
				if (debug > 2) {
					Log(LOG_DEBUG, "<LOC %s", pkt_dump_str(pkt));
					Log(LOG_DEBUG, "  DNF: not connected");
				}
				continue;
			}

#ifdef notdef
			// see if we are sniffing our own bridged traffic
			if (known_remote_eaddr(ETHER(pkt)->ether_shost)) {
				if (debug > 1)
					Log(LOG_DEBUG, "  DNF: Own bridged traffic");
				continue;
			}
#endif

			eaddr_is_local(ETHER(pkt)->ether_shost); // remember local src

			// if destination is known to be local, don't forward
			if (known_local_eaddr(ETHER(pkt)->ether_dhost)) {
				local_packets_not_needing_tunnel++;
				if (debug > 2) {
					Log(LOG_DEBUG, "<LOC %s", pkt_dump_str(pkt));
					Log(LOG_DEBUG, "  DNF: local dest");
				}
				continue;
			}
			if (debug > 1)
				Log(LOG_DEBUG, "<LOC %s", pkt_dump_str(pkt));

			if (debug > 1) {
				if (IS_EBCAST(ETHER(pkt)->ether_dhost)) {
					Log(LOG_DEBUG, "  >TUN  dest is broadcast");
				} else {
					Log(LOG_DEBUG, "  >TUN  src/dst locations unknown");
				}
			}
			outgoing_tunnel_packets++;
			outgoing_tunnel_bytes += pkt->len;
			send_packet_to_remote(pkt);
			busy = 1;
		}
		if (FD_ISSET(tfd, &fds)) { 	// remote from the tunnel
			pkt = read_tunneled_packet();
			if (!pkt)
				continue;
			incoming_tunnel_packets++;
			incoming_tunnel_bytes += pkt->len;

			if (IS_PROTO(pkt)) {
				int proto = *(int *)pkt->data;
				incoming_proto_packets++;
				if (debug > 1) {
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
					return 0;
				default:
					Log(LOG_WARNING, "Unexpected protocol: %d",
						proto);
				}
			} else if (connected) {
				if (debug > 1) {
					Log(LOG_DEBUG, "<TUN  %s",  pkt_dump_str(pkt));
					Log(LOG_DEBUG, "  >LOC");
				}
				eaddr_is_remote(ETHER(pkt)->ether_shost);
				put_local_packet(pkt);
			} else {
				if (debug > 1)
					Log(LOG_DEBUG, "  not connected, ignored");
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

	send_proto(Pbye);
	return 0;
}
