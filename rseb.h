/* rseb.h */

#include <sys/socket.h>
#include <syslog.h>
#include <net/ethernet.h>
#include <net/if.h>

typedef enum packet_proto {
	Phello,
	Phelloback,
	Pheartbeat,
	Pbye,
} packet_proto;

#define PROTO_SIZE	sizeof(packet_proto)
#define IS_PROTO(p)	((p)->len == PROTO_SIZE)
#define PROTO(pkt)	(*(int *)(pkt)->data)

typedef struct packet {
	ssize_t len;
	union {
		const u_char *data;
		struct ether_header *ehdr;
	};
} packet;

#define IS_EBCAST(e)	(!memcmp(((struct ether_addr *)&(e)), &ether_bcast, sizeof(ether_bcast)))

#define IS_EBMCAST(e)	(ETHER_IS_MULTICAST((u_char *)e))
#define IS_BRIDGE_MULTICAST(e)	(((e)->octet[0] == 0x01) && \
				((e)->octet[0] == 0x80) && \
				((e)->octet[0] == 0xc2)) 

#define ESTRLEN	(ETHER_ADDR_LEN*3)


/* main.c */
extern	int debug;
extern	int use_syslog;

/* util.c */
extern	void Log(int level, char *msg, ...);
extern	time_t now(void);
extern	struct ether_addr ether_bcast;

/* debug.c */
extern	char *e_hdr_str(struct ether_header *hdr);
extern	char *pkt_dump_str(packet *p);
extern	void ether_print(struct ether_addr *eaddr, char *buf);
extern	char *sa_str(struct sockaddr *sa);
extern	char *pkt_str(packet *p);
extern	char *proto_str(packet_proto pp);

/* db.c */
extern	void init_db(void);
extern	int known_local_eaddr(struct ether_addr *addr);
extern	int known_remote_eaddr(struct ether_addr *addr);
extern	void eaddr_is_local(struct ether_addr *new);
extern	void eaddr_is_remote(struct ether_addr *new);

extern	char *ether_addr(struct ether_addr *eaddr);
extern	char *hex(u_char *b);
extern	void dump_local_eaddrs(void);
extern	void dump_remote_eaddrs(void);

/* localio.c */
extern	char *local_dev(void);
extern	int init_capio(char *dev);
extern	packet *get_local_packet(int fd);
extern	void put_local_packet(packet *pkt);
