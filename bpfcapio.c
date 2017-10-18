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

int out_fd = -1;

#ifdef DOESNTWORK
// On some FreeBSD devices, bpf outputs don't seem to generate actual broadcast
// packets.  So we use a separate, secret, internal connection to a raw socket
// to do this.

int
open_raw(char *dev) {
	struct ifreq ifr;
	const int on = 1;
	int s;

	s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (s < 0) {
		Log(LOG_ERR, "Cannot open raw device: %s",
			strerror(errno));
		return -1;
	}

	if (setsockopt(s, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		Log(LOG_ERR, "raw device initialization: IP_HDRINCL: %s",
			strerror(errno));
		return -1;
	}

#ifdef broken
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
	if (ioctl (s, BIOCSETIF, &ifr) < 0) {
		Log(LOG_ERR, "BIOSETIF failed for %s: %s", dev,
			strerror(errno));
		return -1;
	}
#endif
	return s;
}
#endif

u_char *bpfbuf = 0;
size_t bpf_buflen;
u_char *bufptr;
int bytes_in_buf = 0;

packet *
get_local_packet(int bpfd) {
	struct bpf_hdr *hdr;
	static packet p;

	if (bytes_in_buf <= 0) {
		int n;

		memset(bpfbuf, 0, bpf_buflen);
		n = bytes_in_buf = read(bpfd, bpfbuf, bpf_buflen);

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

	n = write(out_fd, pkt->data, pkt->len);
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
	int i, bpf_fd = -1;
	struct ifreq ifr;
	u_int32_t enable = 1;
//	u_int32_t disable = 0;
	u_int32_t direction = BPF_D_INOUT;
	struct timeval bpf_timeout = {0, 2000};	// 2 us

	for (i = 0; i < 255; i++) {
                snprintf(device_name, sizeof(device_name), "bpf%u", i);
                snprintf(path, sizeof(path), "/dev/%s", device_name);

		bpf_fd = open(path, O_RDWR);
		if (bpf_fd >= 0)
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
	if (bpf_fd < 0) {
		Log(LOG_ERR, "Could not find /dev/bpfXX");
		return -1;
	}

	if (ioctl(bpf_fd, BIOCGBLEN, &bpf_buflen) < 0) {
		Log(LOG_ERR, "BIOCGBLEN failed for %s: %s", dev,
			strerror(errno));
		return -1;
	}
	Log(LOG_DEBUG, "BPF buffer size %d", bpf_buflen);
	bpfbuf = (u_char *)malloc(bpf_buflen);
	assert(bpfbuf);		// allocate bpf buffer

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
	if (ioctl (bpf_fd, BIOCSETIF, &ifr) < 0) {
		Log(LOG_ERR, "BIOSETIF failed for %s: %s", dev,
			strerror(errno));
		return -1;
	}

	if (ioctl(bpf_fd, BIOCPROMISC, &enable) < 0) {
		Log(LOG_ERR, "BIOCPROMISC failed for %s: %s", dev,
			strerror(errno));
		return -1;
	}

	/* Disable header complete mode: we supply everything */
	if (ioctl(bpf_fd, BIOCSHDRCMPLT, &enable) < 0) {
		Log(LOG_ERR, "BIOCSHDRCMPLT failed for %s: %s",
			dev, strerror(errno));
		return -1;
	}

	/* Do not monitor packets sent from our interface */
	if (ioctl(bpf_fd, BIOCSDIRECTION, &direction) < 0) {
		Log(LOG_ERR, "BIOCSSEESENT failed for %s: %s",
			dev, strerror(errno));
		return -1;
	}

	/* Return immediately when a packet received */
	if (ioctl(bpf_fd, BIOCIMMEDIATE, &enable) < 0) {	// this doesn't seem to work
		Log(LOG_ERR, "BIOCIMMEDIATE failed for %s: %s",
			dev, strerror(errno));
		return -1;
	}

	/* Return immediately when a packet received */
	if (ioctl(bpf_fd, BIOCSRTIMEOUT, &bpf_timeout) < 0) {	// this doesn't seem to work
		Log(LOG_ERR, "BIOCSRTIMEOUT failed for %s: %s",
			dev, strerror(errno));
		return -1;
	}

	out_fd = bpf_fd;

	Log(LOG_DEBUG, "Using %s on fd %d", path, bpf_fd);
	return bpf_fd;
}
