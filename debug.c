/* debug: derived from tcpdump's print-ether */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <netdb.h>

#include "rseb.h"

const struct {
	int type;
	char *label;
} ethertype_values[] = {
    { ETHERTYPE_IP,		"IPv4" },
    { ETHERTYPE_MPLS,		"MPLS unicast" },
    { ETHERTYPE_IPV6,		"IPv6" },
    { ETHERTYPE_PUP,            "PUP" },
    { ETHERTYPE_ARP,            "ARP"},
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

char *
proto_str(packet_proto pp) {
	switch (pp) {
	case Phello:
		return "Hello";
	case Phelloback:
		return "Hello reply";
	case Pheartbeat:
		return "Heartbeat";
	case Pbye:
		return "Bye";
	default: 
		return "Unknown";
	}
}

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

	snprintf(buf, sizeof(buf), "%s > %s  %s", src, dst, 
		e_type_str(ntohs(hdr->ether_type)));
	return buf;
}

char *
hex(u_char *b) {
	static char buf[100];
	snprintf(buf, sizeof(buf), "%.02x %.02x %.02x %.02x  %.02x %.02x %.02x %.02x  %.02x %.02x %.02x %.02x  %.02x %.02x %.02x %.02x  %.02x %.02x %.02x %.02x  %.02x %.02x %.02x %.02x",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
		b[16], b[17], b[18], b[19], b[20], b[21], b[22], b[23]);
	return buf;
}

char *
pkt_dump_str(packet *p) {
	struct ether_header *hdr = (struct ether_header *)p->data;
	static char buf[1000];
	char buf2[1000];
	char *dbuf = "";
	u_short type = ntohs(hdr->ether_type);

	switch (type) {
	case ETHERTYPE_ARP: {
		struct arphdr *ahdr = (struct arphdr *)((u_char *)hdr + sizeof(struct ether_header));
		struct in_addr *sa = (struct in_addr *)ar_spa(ahdr);
		struct in_addr *ta = (struct in_addr *)ar_tpa(ahdr);
		char src[100], tgt[100];

		strncpy(src, inet_ntoa(*sa), sizeof(src));
		strncpy(tgt, inet_ntoa(*ta), sizeof(tgt));

		u_short arp_code = ntohs(ahdr->ar_op);
		switch (arp_code) {
		case ARPOP_REQUEST:
			snprintf(buf2, sizeof(buf2), " request who-has %s tell %s",
				tgt, src);
			dbuf = buf2;
			break;
		case ARPOP_REPLY:
			ether_print((u_char *)ar_tha(ahdr), tgt);
			snprintf(buf2, sizeof(buf2), " reply %s is-at %s",
				src, tgt);
			dbuf = buf2;
			dbuf = buf2;
			break;
		default:
			snprintf(buf2, sizeof(buf2), "  %p+%lu = %p   %s",
				(void *)hdr, (u_long)sizeof(struct ether_header),
				(void *)ahdr,
				hex((u_char *)hdr));
#ifdef notdef
			snprintf(buf2, sizeof(buf2), "  %.04x %.04x %02x %02x %.04x",
				ahdr->ar_hrd, ahdr->ar_pro, ahdr->ar_hln,
				ahdr->ar_pln, ahdr->ar_op);
			snprintf(buf2, sizeof(buf2), " code %d", arp_code);
#endif
			dbuf = buf2;
		}
		break;
	}
	case ETHERTYPE_IP: {
		struct ip *ip = (struct ip *)((u_char *)hdr + sizeof(struct ether_header));
		char src[100], dst[100];
		u_short src_port, dst_port;
		char *proto;

		strncpy(src, inet_ntoa(ip->ip_src), sizeof(src));
		strncpy(dst, inet_ntoa(ip->ip_dst), sizeof(dst));
		switch (ip->ip_p) {
		case IPPROTO_TCP: {
			struct tcphdr *tcph = (struct tcphdr *)((u_char *)ip + sizeof(struct ip));
			proto = "TCP";
			src_port = tcph->th_sport;
			dst_port = tcph->th_dport;
			break;
		}
		case IPPROTO_UDP: {
			struct udphdr *udph = (struct udphdr *)((u_char *)ip + sizeof(struct ip));
			proto = "UDP";
			src_port = udph->uh_sport;
			dst_port = udph->uh_dport;
			break;
		}
			break;
		default: {
			static char buf3[100];
			snprintf(buf3, sizeof(buf3), "IP proto %d", ip->ip_p);
			proto = buf3;
		}
		}

		snprintf(buf2, sizeof(buf2), "  %s %s:%hu -> %s:%hu",
			proto, src, ntohs(src_port),
			dst, ntohs(dst_port));
		dbuf = buf2;
		break;
	}
	case ETHERTYPE_IPV6: {
		break;
	}
	default:
		dbuf = "?";
	}
	snprintf(buf, sizeof(buf), "%s%s", e_hdr_str(hdr), dbuf);
	return buf;
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
	snprintf(obuf, sizeof(obuf), "%s port %d", buf, port);
	return obuf;
}

