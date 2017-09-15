/* rseb.h */

#include <sys/socket.h>
#include <syslog.h>

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
	const u_char *data;
} packet;

#define ETHER(packet)	((struct ether_header *)(packet)->data)

#define IS_EBCAST(e)	(memcmp(e, ether_bcast, ETHER_ADDR_LEN) == 0)


/* main.c */
extern	int debug;
extern	int use_syslog;

/* util.c */
extern	void Log(int level, char *msg, ...);
extern	time_t now(void);

extern	u_char ether_bcast[ETHER_ADDR_LEN];

/* debug.c */
extern	char *e_hdr_str(struct ether_header *hdr);
extern	void ether_print(u_char *eaddr, char *buf);
extern	char *sa_str(struct sockaddr *sa);
extern	char *pkt_str(packet *p);
extern	char *tunnel_str(packet *tp);

/* db.c */
extern	void init_db(void);
extern	int known_local_eaddr(u_char addr[ETHER_ADDR_LEN]);
extern	int known_remote_eaddr(u_char addr[ETHER_ADDR_LEN]);
extern	void add_local_eaddr(u_char new[ETHER_ADDR_LEN]);
extern	void add_remote_eaddr(u_char new[ETHER_ADDR_LEN]);

extern	char *ether_addr(u_char *eaddr);
extern	char *hex(u_char *b);
extern	void dump_local_eaddrs(void);
extern	void dump_remote_eaddrs(void);

/* proto.c */
