/* debug: derived from tcpdump's print-ether */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
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
	snprintf(buf, sizeof(buf), "%.02x %.02x %.02x %.02x  %.02x %.02x %.02x %.02x  %.02x %.02x %.02x %.02x  %.02x %.02x %.02x %.02x",
		b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
	return buf;
}

char *
edump(struct ether_header *hdr) {
	static char buf[1000];
	char buf2[100];
	char *dbuf = "";
	u_short type = ntohs(hdr->ether_type);

	switch (type) {
	case ETHERTYPE_ARP: {
		struct arphdr *ahdr = (struct arphdr *)(hdr + sizeof(struct ether_header));
		u_short arp_code = ntohs(ahdr->ar_op);
		switch (arp_code) {
		case ARPOP_REQUEST:
			dbuf =" request";
			break;
		case ARPOP_REPLY:
			dbuf =" reply";
			break;
		default:
			snprintf(buf2, sizeof(buf2), " %s", hex(&((u_char *)hdr)[12]));

//			snprintf(buf2, sizeof(buf2), " code %d", arp_code);
			dbuf = buf2;
		}
		break;
	}
	case ETHERTYPE_IP:
		break;
	case ETHERTYPE_IPV6:
		break;
	default:
		dbuf = "?";
	}
	snprintf(buf, sizeof(buf), "%s%s", e_hdr_str(hdr), dbuf);
	return buf;
}

#ifdef old
void
dump_ether_header(struct ether_header *hdr) {
	char src[ESTRLEN];
	char dst[ESTRLEN];
	
	ether_print(hdr->ether_shost, src);
	ether_print(hdr->ether_dhost, dst);
	fprintf(stderr, "%s > %s  %s", src, dst, e_type_str(hdr->ether_type));
}


#define IP_V(ip)   (((ip)->ip_v & 0xf0) >> 4)		// from tcpdump

void
dump_ip(packet *pkt) {
	struct ip *ip = (struct ip *)&(pkt->data);
	char src[200], dst[200];
	int family, src_port, dst_port;

	Log(LOG_DEBUG, "IPv%d packet, len = %d", ip->ip_v, pkt->len);

}
packet *pkt
#endif

char *
pkt_str(packet *p) {
//	struct ether_header *hdr = (struct ether_header *)p->data;
//	char *ehdr = e_hdr_str(hdr);

	if (IS_PROTO(p))
		return "(protocol)";
	return hex((void *)p->data);
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
