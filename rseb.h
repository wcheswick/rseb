/* rseb.h */

#include <syslog.h>

typedef enum packet_proto {
	Phello,
	Phelloback,
	Pbye,
} packet_proto;

#define PROTO_SIZE	sizeof(int)

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
extern	char *edump(struct ether_header *hdr);
extern	void ether_print(u_char *eaddr, char *buf);

/* db.c */
extern	void init_db(void);
extern	int known_entry(u_char addr[ETHER_ADDR_LEN]);
extern	void add_entry(u_char addr[ETHER_ADDR_LEN]);
extern	char *ether_addr(u_char *eaddr);
extern	char *hex(u_char *b);
extern	void dump_db(void);

/* proto.c */
