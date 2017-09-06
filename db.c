// db: database of local ethernet addresses

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <net/ethernet.h>
#include <sys/tree.h>           // for the splay routines
#include <assert.h>

#include "rseb.h"


typedef struct ethernet_entry {
	SPLAY_ENTRY(ethernet_entry) next;
	u_char addr[ETHER_ADDR_LEN];
	time_t last_seen;
	long	count;
} ethernet_entry;

SPLAY_HEAD(ethernet_tree, ethernet_entry) local_ethernets;

int
ethernet_compare(ethernet_entry *a, ethernet_entry *b) {
	return memcmp((ethernet_entry *)a->addr, (ethernet_entry *)b->addr, ETHER_ADDR_LEN);
}

SPLAY_PROTOTYPE(ethernet_tree, ethernet_entry, next, ethernet_compare)
SPLAY_GENERATE(ethernet_tree, ethernet_entry, next, ethernet_compare)

void
init_db(void) {
	SPLAY_INIT(&local_ethernets);
}

void
add_entry(u_char new[ETHER_ADDR_LEN]) {
	struct ethernet_entry find, *e;
	memcpy(find.addr, new, sizeof(find.addr));
	e = SPLAY_FIND(ethernet_tree, &local_ethernets, &find);
	if (e) {
		e->count++;
		e->last_seen = now();
		return;
	}
	Log(LOG_DEBUG, "new local: %s", ether_addr(new));

	e = (struct ethernet_entry *)malloc(sizeof(struct ethernet_entry));
	assert(e);
	memset(e, 0, sizeof(struct ethernet_entry));
	memcpy(e->addr, new, sizeof(e->addr));
	e->count = 1;
	e->last_seen = now();
	SPLAY_INSERT(ethernet_tree, &local_ethernets, e);
}

static struct ethernet_entry *
find_entry(u_char addr[ETHER_ADDR_LEN]) {
	struct ethernet_entry find, *e;
	memcpy(find.addr, addr, sizeof(find.addr));
	e = SPLAY_FIND(ethernet_tree, &local_ethernets, &find);
	if (e) {
		e->count++;
		e->last_seen = now();
		return e;
	}
	return 0;
}

int
known_entry(u_char addr[ETHER_ADDR_LEN]) {
	return find_entry(addr) != 0;
}

void
dump_db(void) {
	time_t t = now();
	struct ethernet_entry *e;

	SPLAY_FOREACH(e, ethernet_tree, &local_ethernets) {
		Log(LOG_DEBUG, "%s %7d  %5d",
			ether_addr(e->addr), e->count, t - e->last_seen);
	}
}
