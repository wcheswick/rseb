// bpfcapio.c
//
//	Use the Berkeley packet filter for raw I/O.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <errno.h>

#include <net/bpf.h>
#include <fcntl.h>

#include "rseb.h"

int rawfd = -1;

size_t bpf_buflen;

packet *
get_local_packet(void) {
	static u_char buf[20000];
	int n = read(rawfd, buf, sizeof(buf));
	static packet p;

	p.data = buf;
	p.len = n;
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

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
	if (ioctl (rawfd, BIOCSETIF, &ifr) < 0) {
		Log(LOG_ERR, "BIOSETIF failed for %s: %s", dev,
			strerror(errno));
		return -1;
	}

	if (ioctl(rawfd, BIOCGBLEN, &bpf_buflen) < 0) {
		Log(LOG_ERR, "BIOCGBLEN failed for %s: %s", dev,
			strerror(errno));
		return -1;
	}
	Log(LOG_DEBUG, "BFP buf len = %d", bpf_buflen);

	/* Set header complete mode */
	if (ioctl(rawfd, BIOCSHDRCMPLT, &enable) < 0) {
		Log(LOG_ERR, "BIOCSHDRCMPLT failed for %s: %s",
			dev, strerror(errno));
		return -1;
	}

	/* Monitor packets sent from our interface */
	if (ioctl(rawfd, BIOCSSEESENT, &disable) < 0) {
		Log(LOG_ERR, "BIOCSSEESENT failed for %s: %s",
			dev, strerror(errno));
		return -1;
	}

#ifdef notdef
	/* Return immediately when a packet received */
	if (ioctl(rawfd, BIOCIMMEDIATE, &enable) < 0) {
		Log(LOG_ERR, "BIOCIMMEDIATE failed for %s: %s",
			dev, strerror(errno));
		return -1;
	}
#endif

	Log(LOG_DEBUG, "Using %s on fd %d", path, rawfd);
	return rawfd;
}
