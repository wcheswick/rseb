// pcapio.c
//
//	pcap interface to local network. 

//	XXX  Has buffering problems.

#include <pcap.h>
#include <assert.h>

#include "rseb.h"

pcap_t *pcap_handle = 0;
char pcap_err_buf[PCAP_ERRBUF_SIZE];

// #define PCAP_FILTER	"arp or broadcast"

// return an fd for the pcap device if all is ok

int
init_capio(char *dev) {
#ifdef brokenfilter
	struct bpf_program fp;
#endif
	int fd, rc;

	assert(pcap_handle == NULL);	// call only once

	pcap_handle = pcap_create(dev, pcap_err_buf);
	if (pcap_handle == NULL) {
		Log(LOG_ERR, "pcap_create: could not start pcap, interface '%s': %s",
			dev, pcap_geterr(pcap_handle));
		return -1;
	}
	if (pcap_set_timeout(pcap_handle, 1) != 0) {
		Log(LOG_ERR, "pcap_set_timeout, interface: %s",
			pcap_geterr(pcap_handle));
		return -1;
	}
	if (pcap_set_immediate_mode(pcap_handle, 1) != 0) {
		Log(LOG_ERR, "pcap_set_immediate_mode: %s", 
			pcap_geterr(pcap_handle));
		return -1;
	}

	// ignore the outgoing traffic, which we may well have generated
	if (!pcap_setdirection(pcap_handle, PCAP_D_IN)) {
		Log(LOG_ERR, "pcap_setdirection: pcap cannot set capture direction: %s", 
			pcap_geterr(pcap_handle));
		return -1;
	}

	rc = pcap_activate(pcap_handle);
	if (rc > 0) {		// pcap warning
		switch (rc) {
		case PCAP_WARNING_PROMISC_NOTSUP:
			Log(LOG_ERR, "pcap_activate: pcap promiscous unsupported");
			return -1;
		case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
			Log(LOG_ERR, "pcap_activate: time stamp type unsupported");
			break;
		case PCAP_WARNING:
			Log(LOG_ERR, "pcap_activate warning: %s",
				pcap_geterr(pcap_handle));
			break;
		default:
 			Log(LOG_ERR, "pcap_activate unknown warning");
		}
	} else if (rc < 0) {	// pcap error
		Log(LOG_ERR, "pcap_activate error %d: %s", 
			rc, pcap_geterr(pcap_handle));
		return -1;
	}
	if (!pcap_set_snaplen(pcap_handle, 2000)) {
		Log(LOG_ERR, "pcap cannot set snap length: %s", 
			pcap_geterr(pcap_handle));
		return -1;
	}
	if (!pcap_set_promisc(pcap_handle, 1)) {
		Log(LOG_ERR, "pcap_set_promisc: pcap cannot set promiscuous mode: %s", 
			pcap_geterr(pcap_handle));
		return -1;
	}

	if (pcap_setnonblock(pcap_handle, 1, pcap_err_buf) < 0) {
		Log(LOG_ERR, "pcap_setnonblock failed: %s", pcap_geterr(pcap_handle));
		return -1;
	}
	if (pcap_datalink(pcap_handle) != DLT_EN10MB) {
		Log(LOG_ERR, "pcap_datalink: interface '%s' not supported", dev);
		return -1;
	}
	if (!pcap_set_buffer_size(pcap_handle, 100000)) {
		Log(LOG_ERR, "pcap_set_buffer_size: cannot set buffer size: %s", 
			pcap_geterr(pcap_handle));
		return -1;
	}

#ifdef brokenfilter
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
#endif

	fd = pcap_get_selectable_fd(pcap_handle);
	if (fd < 0) {
		Log(LOG_ERR, "pcap_get_selectable_fd: device unsuitable for select '%s'", 
			dev);
		return -1;
	}

	return fd;
}

packet *
get_local_packet(int bpfd) {	// we ignore the fd, we have the pcap_handle
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

	if (phdr->caplen != phdr->len) {
		Log(LOG_WARNING, "short packet, %d != %d",
			phdr->caplen != phdr->len);
	}
	p.len = phdr->caplen;
	return &p;
}

void
put_local_packet(packet *pkt) {
	int n;

	n = pcap_sendpacket(pcap_handle, pkt->data, pkt->len);
	if (n < 0) {
		Log(LOG_WARNING, "pcap raw write error: %s",
			pcap_geterr(pcap_handle));
	}
}

char *
local_dev(void) {
	char *dev = pcap_lookupdev(pcap_err_buf);
	if (dev == NULL) {
		Log(LOG_ERR, "pcap cannot find default device: %s",
			pcap_err_buf);
		return NULL;
	}
	return dev;
}
