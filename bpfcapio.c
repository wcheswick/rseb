// bpfcapio.c
//
//	Use the Berkeley packet filter for raw I/O.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/bpf.h>
#include <assert.h>

#include "rseb.h"

int rawfd = -1;

u_char *bpfbuf = 0;
size_t bpf_buflen;
u_char *bufptr;
int bytes_in_buf = 0;

packet *
get_local_packet(void) {
	struct bpf_hdr *hdr;
	static packet p;

	if (bytes_in_buf <= 0) {
		int n;

		memset(bpfbuf, 0, bpf_buflen);
		n = bytes_in_buf = read(rawfd, bpfbuf, bpf_buflen);

		if (n <= 0) {
			if (n < 0)
			Log(LOG_WARNING, "BPF read error: %s", 
				strerror(errno));
			return 0;
		}
		bufptr = bpfbuf;
		bytes_in_buf = n;
	}

	hdr = (struct bpf_hdr *)bufptr;
	p.data = ((u_char *)hdr + hdr->bh_hdrlen);
	p.len = hdr->bh_caplen;

	bufptr += BPF_WORDALIGN(hdr->bh_hdrlen + hdr->bh_caplen);
	bytes_in_buf -= (bufptr - (u_char *)hdr);
	return &p;
}

void
put_local_packet(packet *pkt) {
	int n;

	n = write(rawfd, pkt->data, pkt->len);
	if (n < 0) {
		Log(LOG_WARNING, "raw write error: %s",
			strerror(errno));
	}
	if (n != pkt->len)
		Log(LOG_WARNING, "raw write short packet, %d != %d",
			n, pkt->len);
}

char *
local_dev(void) {
	struct ifreq *ifreq;
	struct ifconf ifconf;
	static char buf[16384];
	int i;
	size_t len;
	int rfd = -1;

	rfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (rfd < 0) {
		Log(LOG_ERR, "Cannot open raw device: %s",
			strerror(errno));
		return NULL;
	}

	ifconf.ifc_len=sizeof(buf);
	ifconf.ifc_buf=buf;
	if (ioctl(rfd, SIOCGIFCONF, &ifconf)!=0) {
		Log(LOG_ERR, "Cannot list interfaces (SIOCGIFCONF): %s",
			strerror(errno));
		close(rfd);
		return NULL;
	}

	ifreq=ifconf.ifc_req;
	for (i=0; i<ifconf.ifc_len; ) {
		short flags = ifreq->ifr_flags;
//Log(LOG_DEBUG, "%.04x interface %s", flags, ifreq->ifr_name);
//		if ((flags & IFF_UP) && !(flags & IFF_LOOPBACK))
		if (!(flags & IFF_LOOPBACK)) {
			close(rfd);
			return ifreq->ifr_name;
		}

		/* some systems have ifr_addr.sa_len and adjust the length that
		 * way, but not mine. weird */
#ifndef linux
		len=IFNAMSIZ + ifreq->ifr_addr.sa_len;
#else
		len=sizeof(*ifreq);
#endif
		ifreq=(struct ifreq *)((char *)ifreq+len);
		i+=len;
	}
	close(rfd);
	return "???";
}

// What about AF_INET6?

int
init_capio(char *dev) {
	static char device_name[10];
	char path[20];
	int i;
	struct ifreq ifr;
	u_int32_t enable = 1;
	u_int32_t disable = 0;
	u_int32_t direction = BPF_D_INOUT;

	for (i = 0; i < 255; i++) {
                snprintf(device_name, sizeof(device_name), "bpf%u", i);
                snprintf(path, sizeof(path), "/dev/%s", device_name);

		rawfd = open(path, O_RDWR);
		if (rawfd >= 0)
			break;

		switch (errno) {
		case EBUSY:
                	continue;
		default:
			Log(LOG_ERR, "Unexpected BFP open error: %s",
				strerror(errno));
			return -1;
		}
        }
	if (rawfd < 0)
		return -1;

	if (ioctl(rawfd, BIOCGBLEN, &bpf_buflen) < 0) {
		Log(LOG_ERR, "BIOCGBLEN failed for %s: %s", dev,
			strerror(errno));
		return -1;
	}
	Log(LOG_DEBUG, "BPF buffer size %d", bpf_buflen);
	bpfbuf = (u_char *)malloc(bpf_buflen);
	assert(bpfbuf);		// allocate bpf buffer

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
	if (ioctl (rawfd, BIOCSETIF, &ifr) < 0) {
		Log(LOG_ERR, "BIOSETIF failed for %s: %s", dev,
			strerror(errno));
		return -1;
	}

	if (ioctl(rawfd, BIOCPROMISC, &enable) < 0) {
		Log(LOG_ERR, "BIOCPROMISC failed for %s: %s", dev,
			strerror(errno));
		return -1;
	}

	/* Disable header complete mode: we supply everything */
	if (ioctl(rawfd, BIOCSHDRCMPLT, &disable) < 0) {
		Log(LOG_ERR, "BIOCSHDRCMPLT failed for %s: %s",
			dev, strerror(errno));
		return -1;
	}

	/* Do not monitor packets sent from our interface */
	if (ioctl(rawfd, BIOCSDIRECTION, &direction) < 0) {
		Log(LOG_ERR, "BIOCSSEESENT failed for %s: %s",
			dev, strerror(errno));
		return -1;
	}

	/* Return immediately when a packet received */
	if (ioctl(rawfd, BIOCIMMEDIATE, &enable) < 0) {
		Log(LOG_ERR, "BIOCIMMEDIATE failed for %s: %s",
			dev, strerror(errno));
		return -1;
	}

	Log(LOG_DEBUG, "Using %s on fd %d", path, rawfd);
	return rawfd;
}

// set up a filter to ignore tunnel traffic. This should be done
// with a filter, but that takes three wise men and a virgin, and
// I need to get this working.

u_short		excluded_ether_type;
struct ether_addr excluded_ether_host_a;
struct ether_addr excluded_ether_host_b;
u_char		excluded_protocol;	// iff ethertype ip or ipv6
u_short		excluded_port;		// iff TCP or UDP, destination port

void
exclude_tunnel_endpoints(packet *p) {
	uint8_t *protohdr;
	char exclude_str[300] = "";

Log(LOG_DEBUG, "filtering based on packet %s", pkt_dump_str(p));

	excluded_ether_type = ntohs(p->ehdr->ether_type);
	memcpy(&excluded_ether_host_a, &p->ehdr->ether_shost, sizeof(excluded_ether_host_a));
	memcpy(&excluded_ether_host_b, &p->ehdr->ether_dhost, sizeof(excluded_ether_host_a));

	strcat(exclude_str, ether_addr(&excluded_ether_host_a));
	strcat(exclude_str, " ");
	strcat(exclude_str, ether_addr(&excluded_ether_host_b));

	switch (excluded_ether_type) {
	case ETHERTYPE_IP: {
		struct ip *ip = (struct ip *)((u_char *)p->ehdr +
			sizeof(struct ether_header));
		int proto = ip->ip_p;

		strcat(exclude_str, " IPv4");
		protohdr = ((u_char *)ip + sizeof(struct ip));
		switch (proto) {
		case IPPROTO_TCP: {
			struct tcphdr *tcph = (struct tcphdr *)((u_char *)ip + 
				sizeof(struct ip));
			excluded_protocol = proto;
			strcat(exclude_str, " TCP");
			excluded_port = ntohs(tcph->th_dport);
			break;
		}
		case IPPROTO_UDP: {
			struct udphdr *udph = (struct udphdr *)((u_char *)ip +
				sizeof(struct ip));
			excluded_protocol = proto;
			strcat(exclude_str, " UDP");
			excluded_port = ntohs(udph->uh_dport);
			break;
		}
		case IPPROTO_ICMP:
		default: 
			;
		}
		break;
	}
	case ETHERTYPE_IPV6: {
		struct ip6_hdr *ip6 = (struct ip6_hdr *)((u_char *)p->ehdr + 
			sizeof(struct ether_header));
		int proto = ip6->ip6_nxt;

		strcat(exclude_str, " IPv6");
		switch (proto) {
		case IPPROTO_TCP: {
			struct tcphdr *tcph = (struct tcphdr *)((u_char *)ip6 + 
				sizeof(*ip6));
			excluded_protocol = proto;
			strcat(exclude_str, " TCP");
			excluded_port = ntohs(tcph->th_dport);
			break;
		}
		case IPPROTO_UDP: {
			struct udphdr *udph = (struct udphdr *)((u_char *)ip6 +
				sizeof(*ip6));
			excluded_protocol = proto;
			strcat(exclude_str, " UDP");
			excluded_port = ntohs(udph->uh_dport);
			break;
		}
		case IPPROTO_ICMP:
		default: 
			;
		}
	}
	default:
		;
	}
	Log(LOG_DEBUG, "filtering %s", exclude_str);
abort();
}
