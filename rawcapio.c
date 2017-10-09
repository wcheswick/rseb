// rawcapio.c
//
//	raw interface to local network. Tested with FreeBSD.

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <net/bpf.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <errno.h>

#include "rseb.h"


XXX this crashes FreeBSD at the moment.

int rawfd = -1;

struct ifreq if_idx;	// for writing to the raw interface

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
// XXX which interface?

int
init_capio(char *dev) {
	struct ifreq ifr;
	const int on = 1;

	rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (rawfd < 0) {
		Log(LOG_ERR, "Cannot open raw device: %s",
			strerror(errno));
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", dev);

	if (setsockopt(rawfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
		Log(LOG_ERR, "raw device initialization: IP_HDRINCL: %s",
			strerror(errno));
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, dev, sizeof(ifr.ifr_name));
	ifr.ifr_flags |= IFF_PROMISC;
	if (ioctl (rawfd, SIOCSIFFLAGS, &ifr) < 0) {
		Log(LOG_ERR, "init_capio of %s: %s", dev,
			strerror(errno));
		return -1;
	}

#ifdef notdef
	n = 1500;
	if (setsockopt(rawfd, SOL_SOCKET, SO_SNDBUF, &n, sizeof(n)) < 0) {
		perror("gre_catch: SO_SNDBUF");
		exit(4);
	}
set to if
set promis
others?
#endif
	
	return rawfd;
}
