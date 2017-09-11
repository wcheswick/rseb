// db: database of local ethernet addresses

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <net/ethernet.h>
#include <sys/tree.h>           // for the splay routines
#include <assert.h>

#include "rseb.h"

int db_debug = 0;	// internal database debugging

typedef struct ethernet_entry {
	SPLAY_ENTRY(ethernet_entry) next;
	u_char addr[ETHER_ADDR_LEN];
	time_t last_seen;
	long	count;
} ethernet_entry;

SPLAY_HEAD(ethernet_tree, ethernet_entry) local_eaddrs, remote_eaddrs;

int
ethernet_compare(ethernet_entry *a, ethernet_entry *b) {
	return memcmp((ethernet_entry *)a->addr, (ethernet_entry *)b->addr, ETHER_ADDR_LEN);
}

SPLAY_PROTOTYPE(ethernet_tree, ethernet_entry, next, ethernet_compare)
SPLAY_GENERATE(ethernet_tree, ethernet_entry, next, ethernet_compare)

void
init_db(void) {
	SPLAY_INIT(&local_eaddrs);
	SPLAY_INIT(&remote_eaddrs);
}

static void
add_entry(u_char new[ETHER_ADDR_LEN], struct ethernet_tree *root) {
	struct ethernet_entry find, *e;

	if (IS_EBCAST(new))
		return;

	memcpy(find.addr, new, sizeof(find.addr));
	e = SPLAY_FIND(ethernet_tree, root, &find);
	if (e) {
		e->count++;
		e->last_seen = now();
		return;
	}
	if (db_debug)
		Log(LOG_DEBUG, "new local: %s", ether_addr(new));

	e = (struct ethernet_entry *)malloc(sizeof(struct ethernet_entry));
	assert(e);
	memset(e, 0, sizeof(struct ethernet_entry));
	memcpy(e->addr, new, sizeof(e->addr));
	e->count = 1;
	e->last_seen = now();
	SPLAY_INSERT(ethernet_tree, root, e);
}

void
add_remote_eaddr(u_char new[ETHER_ADDR_LEN]) {
	if (IS_EBCAST(new))
		return;
	if (db_debug)
		Log(LOG_DEBUG," add rem key %s", ether_addr(new));
	add_entry(new, &remote_eaddrs);
}

void
add_local_eaddr(u_char new[ETHER_ADDR_LEN]) {
	if (IS_EBCAST(new))
		return;
	if (db_debug)
		Log(LOG_DEBUG," add loc key %s", ether_addr(new));
	add_entry(new, &local_eaddrs);
}

static struct ethernet_entry *
find_entry(u_char addr[ETHER_ADDR_LEN], struct ethernet_tree *root) {
	struct ethernet_entry find, *e;
	memcpy(find.addr, addr, sizeof(find.addr));
	e = SPLAY_FIND(ethernet_tree, root, &find);
	if (e) {
		e->count++;
		e->last_seen = now();
		return e;
	}
	return 0;
}

int
known_local_eaddr(u_char addr[ETHER_ADDR_LEN]) {
	int rc;

	if (IS_EBCAST(addr))
		return 0;

	rc = find_entry(addr, &local_eaddrs) != 0;
	if (db_debug)
		Log(LOG_DEBUG,"     loc key %s %s",
			ether_addr(addr), rc ? "YES" : "NO");
	return rc;
}

int
known_remote_eaddr(u_char addr[ETHER_ADDR_LEN]) {
	int rc;

	if (IS_EBCAST(addr))
		return 0;

	rc = find_entry(addr, &remote_eaddrs) != 0;
	if (db_debug)
		Log(LOG_DEBUG,"     rem key %s %s",
			ether_addr(addr), rc ? "YES" : "NO");
	return rc;
}

void
dump_local_eaddrs(void) {
	time_t t = now();
	struct ethernet_entry *e;

	if (!db_debug)
		return;
	
	Log(LOG_DEBUG, "Local MACs");
	SPLAY_FOREACH(e, ethernet_tree, &local_eaddrs) {
		Log(LOG_DEBUG, "%s %7d  %5d",
			ether_addr(e->addr), e->count, t - e->last_seen);
	}
}

void
dump_remote_eaddrs(void) {
	time_t t = now();
	struct ethernet_entry *e;
	
	Log(LOG_DEBUG, "Remote MACs:");
	SPLAY_FOREACH(e, ethernet_tree, &remote_eaddrs) {
		Log(LOG_DEBUG, "%s %7d  %5d",
			ether_addr(e->addr), e->count, t - e->last_seen);
	}
}
