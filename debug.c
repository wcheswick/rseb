/* debug: derived from tcpdump's print-ether */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>

#include "rseb.h"

const struct {
	int type;
	char *label;
} ethertype_values[] = {
    { ETHERTYPE_IP,		"ip" },
    { ETHERTYPE_MPLS,		"MPLS unicast" },
    { ETHERTYPE_IPV6,		"ipv6" },
    { ETHERTYPE_PUP,            "PUP" },
    { ETHERTYPE_ARP,            "arp"},
    { ETHERTYPE_REVARP,         "Reverse ARP"},
    { ETHERTYPE_NS,             "NS" },
    { ETHERTYPE_SPRITE,         "Sprite" },
    { ETHERTYPE_TRAIL,          "Trail" },
    { ETHERTYPE_MOPDL,          "MOP DL" },
    { ETHERTYPE_MOPRC,          "MOP RC" },
    { ETHERTYPE_DN,             "DN" },
    { ETHERTYPE_LAT,            "LAT" },
    { ETHERTYPE_SCA,            "SCA" },
    { ETHERTYPE_LANBRIDGE,      "Lanbridge" },
    { ETHERTYPE_DECDNS,         "DEC DNS" },
    { ETHERTYPE_DECDTS,         "DEC DTS" },
    { ETHERTYPE_VEXP,           "VEXP" },
    { ETHERTYPE_VPROD,          "VPROD" },
    { ETHERTYPE_ATALK,          "Appletalk" },
    { ETHERTYPE_AARP,           "Appletalk ARP" },
    { ETHERTYPE_IPX,            "IPX" },
    { ETHERTYPE_PPP,            "PPP" },
    { ETHERTYPE_SLOW,           "Slow Protocols" },
    { ETHERTYPE_LOOPBACK,       "Loopback" },
    { 0, NULL}
};

#define ESTRLEN	(ETHER_ADDR_LEN*3)

void
ether_print(u_char *eaddr, char *buf) {
	snprintf(buf,  ESTRLEN, "%.02x:%.02x:%.02x:%.02x:%.02x:%.02x",
		eaddr[0] & 0xff, eaddr[1] & 0xff, eaddr[2] & 0xff,
		eaddr[3] & 0xff, eaddr[4] & 0xff, eaddr[5] & 0xff);
}

char *
ether_addr(u_char eaddr[ETHER_ADDR_LEN]) {
	static char buf[100];

	snprintf(buf,  ESTRLEN, "%.02x:%.02x:%.02x:%.02x:%.02x:%.02x",
		eaddr[0] & 0xff, eaddr[1] & 0xff, eaddr[2] & 0xff,
		eaddr[3] & 0xff, eaddr[4] & 0xff, eaddr[5] & 0xff);
	return buf;
}

char *
hex(u_char *b) {
	static char buf[100];
	snprintf(buf, sizeof(buf), "%.02x %.02x %.02x %.02x  %.02x %.02x %.02x %.02x  %.02x %.02x %.02x %.02x  %.02x %.02x %.02x %.02x",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
	return buf;
}

char *
icmp_code_str(int code) {
        static char buf[100];

        switch(code) {
        case ICMP_UNREACH_PORT:
                return "Unreachable: port";
        case ICMP_UNREACH_NET:
                return "Unreachable: network";
        case ICMP_UNREACH_HOST:
                return "Unreachable: host";
        case ICMP_UNREACH_PROTOCOL:
                return "Unreachable: protocol";
        case ICMP_UNREACH_NET_UNKNOWN:
                return "Unreachable: unknown net";
        case ICMP_UNREACH_HOST_UNKNOWN:
                return "Unreachable: unknown host";
        case ICMP_UNREACH_ISOLATED:
                return "Unreachable: source host isolated";
        case ICMP_UNREACH_NET_PROHIB:
                return "Unreachable: prohibited access net";
        case ICMP_UNREACH_HOST_PROHIB:
                return "Unreachable: prohibited access host";
        case ICMP_UNREACH_NEEDFRAG:
                return "Unreachable: need frag";
        case ICMP_UNREACH_SRCFAIL:
                return "Unreachable: source route failed";
        case ICMP_UNREACH_TOSNET:
                return "Unreachable: bad tos for net";
        case ICMP_UNREACH_TOSHOST:
                return "Unreachable: bad tos for host";
        case ICMP_UNREACH_FILTER_PROHIB:
                return "Unreachable: filtered";
        case 14:
                return "Unreachable: precedence violation";
        case 15:
                return "Unreachable: precedence too low";
        default:
                sprintf(buf, "Unknown ICMP error #%d", code);
                return  buf;
        }
}

char *
icmp_type_str(u_char t) {
        static char *ttab[] = {
        "Echo Reply",   "ICMP 1",       "ICMP 2",       "Dest Unreachable",
        "Source Quench", "Redirect",    "ICMP 6",       "ICMP 7",
        "Echo",         "router advertisement", "router solicitation",
        "Time Exceeded", "Param Problem", "Timestamp",  "Timestamp Reply",
        "Info Request", "Info Reply", "mask request", "mask reply"
        };

        if(t > sizeof(ttab)/sizeof(char *))
                return "OUT-OF-RANGE";

        return ttab[t];
}


char *
sa_str(struct sockaddr *sa) {
	static char obuf[200];
	char buf[100];
	int port;

	switch (sa->sa_family) {
	case AF_INET: {
		struct sockaddr_in *sa4 = (struct sockaddr_in *)sa;
		inet_ntop(sa->sa_family, &sa4->sin_addr,
			buf, sizeof(buf));
		port = ntohs(sa4->sin_port);
		break;
	}
	case AF_INET6: {
		struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)sa;
		inet_ntop(sa->sa_family, &sa6->sin6_addr,
			buf, sizeof(buf));
		port = ntohs(sa6->sin6_port);
		break;
	}
	default:
		port = 0;
		snprintf(buf, sizeof(buf), "dump_sa: unknown family: %d", sa->sa_family);
	}
	snprintf(obuf, sizeof(obuf), "%s:%d", buf, port);
	return obuf;
}

char *
e_type_str(u_short type) {
	int i;
	static char buf[20];

	for (i=0; ethertype_values[i].type; i++)
		if (ethertype_values[i].type == type)
			return ethertype_values[i].label;
	snprintf(buf, sizeof(buf), "0x%.04x", type);
	return buf;
}

char *
e_hdr_str(struct ether_header *hdr) {
	char src[ESTRLEN];
	char dst[ESTRLEN];
	static char buf[1000];
	
	ether_print(hdr->ether_shost, src);
	ether_print(hdr->ether_dhost, dst);

	snprintf(buf, sizeof(buf), "%s > %s  %s ", src, dst, 
		e_type_str(ntohs(hdr->ether_type)));
	return buf;
}

char *
pkt_str(packet *pkt) {
	struct ether_header *hdr = (struct ether_header *)pkt->data;
	static char buf[1000];
	u_short type = ntohs(hdr->ether_type);
	char buf2[100];
	char *dbuf = "";

	switch (type) {
	case ETHERTYPE_ARP: {
		struct arphdr *ahdr = (struct arphdr *)&pkt->data[ETHER_HDR_LEN];
		u_short arp_code = ntohs(ahdr->ar_op);
		switch (arp_code) {
		case ARPOP_REQUEST:
			if (ntohs(ahdr->ar_hrd) == ARPHRD_ETHER &&
			    ntohs(ahdr->ar_op) == ARPOP_REQUEST) {
				struct in_addr *target = (struct in_addr *)ar_tpa(ahdr);
				struct in_addr *requester = (struct in_addr *)ar_spa(ahdr);
				char tbuf[100];
				strncpy(tbuf, inet_ntoa(*target), sizeof(tbuf));
				snprintf(buf2, sizeof(buf2), " who has %s tell %s",
					tbuf, inet_ntoa(*requester));
				dbuf = buf2;
			} else
				dbuf = "arp huh?";
			break;
		case ARPOP_REPLY:
			dbuf = " reply";
			break;
		default:
			snprintf(buf2, sizeof(buf2), " %s code %d",
				hex((u_char *)ahdr),  arp_code);
			dbuf = buf2;
		}
		break;
	}
	case ETHERTYPE_IP: {
		struct ip *ip = (struct ip *)&pkt->data[ETHER_HDR_LEN];
		size_t ip_hl = ip->ip_hl<<2;
		struct in_addr src, dst;
		char src_buf[100];
		char dst_buf[100];

		memcpy(&src, &ip->ip_src, sizeof(src));
		memcpy(&dst, &ip->ip_dst, sizeof(src));
		snprintf(src_buf, sizeof(src_buf), "%s", inet_ntoa(src));
		snprintf(dst_buf, sizeof(dst_buf), "%s", inet_ntoa(dst));

		switch (ip->ip_p) {
		case IPPROTO_ICMP: {
			struct icmp *icmp = (struct icmp *)&pkt->data[ip_hl];
			snprintf(buf2, sizeof(buf2), "ICMP %s: %s", 
				icmp_type_str(icmp->icmp_type),
				icmp_code_str(icmp->icmp_code));
			dbuf = buf2;
			break;
		}
		case IPPROTO_TCP: {
			struct tcphdr *tcp = (struct tcphdr *)&pkt->data[ip_hl];
			snprintf(buf2, sizeof(buf2), "TCP %s:%d > %s:%d", 
				src_buf, ntohs(tcp->th_sport),
				dst_buf, ntohs(tcp->th_dport));
			dbuf = buf2;
			break;
		}
		case IPPROTO_UDP: {
			struct udphdr *udp = (struct udphdr *)&pkt->data[ip_hl];
			snprintf(buf2, sizeof(buf2), "UDP %s:%d > %s:%d   %s", 
				src_buf, ntohs(udp->uh_sport),
				dst_buf, ntohs(udp->uh_dport),
				hex((u_char *)&pkt->data[ip_hl]));
			dbuf = buf2;
			break;
		}
		case IPPROTO_IGMP: {
			snprintf(buf2, sizeof(buf2), "IGMP %s > %s", src_buf, dst_buf);
			dbuf = buf2;
			break;
		}
		default:
			snprintf(buf2, sizeof(buf2), " type %d", ip->ip_p);
			dbuf = buf2;
		}
		break;
	}
	case ETHERTYPE_IPV6:
		dbuf = "v6";
		break;
	default:
		dbuf = "?";
	}
	snprintf(buf, sizeof(buf), "%s%s", e_hdr_str(hdr), dbuf);
	return buf;
}

char *proto_str[] = {
	"Phello",
	"Phelloback",
	"Pheartbeat",
	"Pbye",
};

char *
tunnel_str(packet *tp) {
	if (IS_PROTO(tp)) {
		static char buf[100];
		int proto = PROTO(tp);

		if (proto < sizeof(proto_str)*sizeof(proto_str[0]))
			snprintf(buf, sizeof(buf), "proto %s", proto_str[proto]);
		else {
			snprintf(buf, sizeof(buf), "proto unknown: 0x%.08x",
				proto);
		}
		return buf;
	}
	return pkt_str(tp);
}
