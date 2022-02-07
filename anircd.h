#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <sys/ioctl.h>
#include "config.h"
#include "numeric.h"

#ifdef DEBUG
#include <dmalloc.h>
#endif
#ifdef SSL_GNUTLS
#include <gnutls/gnutls.h>
#include <gcrypt.h>
#endif

/* config/default settings */
#define CONFIG_FILE	"anircd.conf"
#define MOTD_FILE	"anircd.motd"
#define DEF_PORT	6667
#define DEF_SNAME	"anircd.local"
#define DEF_SDESC	"anircd server"
#define DEF_MAXUSERS	500
#define DEF_MAXCHANS	50
#define DEF_SSLKEY	"ircd.pem"
#define LOG_FILE	"anircd.log"

/* To detect Tor users, #define this: */
#undef TOR_DETECT

#define MAX_QUIT		256
#define MAX_NICKLEN		32
#define MAX_CHANLEN		32
#define MAX_MSG			10
#define MAX_UINBUF		8192
#define MAX_UOBUF		8192
#define MAX_CHANS		10
#define MAX_REALNAME		32
#define MAX_IDENT		32

/* For now, this may change in future */
#define log_notice		log_error

extern char	*c_sname, *c_sdesc, *c_sslkey;
extern int	c_port, c_maxusers, c_maxchans;

int config_load(char *file);

/* user/chan struct management */
#define IsChan(x)	(*x == '#')

typedef struct user_ User;
typedef struct channel_ Chan;

struct user_
{
	User	*next, *prev;
	char	*nick;
	char	*host;
	char	*realname;
	char	*ident;
	Chan	**chans;
	int	nchans;
	int	flags;
	time_t	signon;

	unsigned char	*inbuf;
	int	inlen;

	unsigned char	*outbuf;
	int	outlen;

	int	s;
	int	nmcnt;
#ifdef SSL_GNUTLS
	gnutls_session_t	ssl;
#endif
};

struct channel_
{
	Chan	*next, *prev;
	char	*name;
	User	**users;
	int	nusers;
};

#ifdef SSL_GNUTLS
#define UFL_SSLDONE	0x01
#endif
#define UFL_HAVEUSER	0x02
#define UFL_HAVENICK	0x04
#define UFL_REG		0x08

/* uc funcs */
void uc_init(void);
Chan *chan_new(char *name);
int chan_del(Chan *c);
Chan *chan_find(char *name);
int chan_finduidx(User *u, Chan *c);
int chan_adduent(User *u, Chan *c);
int chan_deluent(User *u, Chan *c);
User *user_new(int s);
void user_move(User *u, char *new);
int user_del(User *u);
User *user_find(char *nick);
int user_findcidx(User *u, Chan *c);
void user_kill(User *u, char *message);
void user_kill2(User *u, char *message);

extern User *ulist[128];
extern Chan *clist[128];
extern int g_numchans, g_numusers, g_maxfd;

/* process functions */
unsigned char *process_read(User *u, int *n);
int process_write(User *u);
int process_inbuf(User *u, char *buf);

/* util/sock functions */
int log_init(void);
void strtoupper(char *s);
void strip(char *s);
int sock_nonblock(int fd);
void load_motd(void);
void send_motd(User *u);
void free_motd(void);
void rehash_motd(int);
void send_buf(User *u, char *buf);
void send_cmd(User *u, char *prefix, char *fmt, ...);
void send_cmd_nobuf(User *u, char *prefix, char *fmt, ...);
void send_num(User *u, int num, char *cmd, char *fmt, ...);
int send_ucmd_chanbutone(User *u, char *fmt, ...);
int send_ucmd_schanbutone(User *u, Chan *c, char *fmt, ...);
int log_error(char *s, ...);
int validate_nick(char *s);
int validate_chan(char *s);
int validate_gen(char *s, int fl);
int send_ucmd_one(User *from, User *to, char *fmt, ...);
int send_ucmd_schan(User *u, Chan *c, char *fmt, ...);
void snotice(User *u, char *fmt, ...);

/* SSL */
#ifdef SSL_GNUTLS
#define DH_BITS 1024
int init_SSL(char *key_file);
extern gnutls_certificate_credentials_t x509_cred;
extern gnutls_priority_t priority_cache;
#endif

/* commands */
void cmd_quit(User *u, char *cmd, int ac, char **av);
void cmd_names(User *u, char *cmd, int ac, char **av);
void cmd_do_names(User *u, Chan *c);
void cmd_join(User *u, char *cmd, int ac, char **av);
void cmd_register(User *u);
void cmd_user(User *u, char *cmd, int ac, char **av);
void cmd_nick(User *u, char *cmd, int ac, char **av);
void cmd_quit(User *u, char *cmd, int ac, char **av);
void cmd_part(User *u, char *cmd, int ac, char **av);
void cmd_do_lusers(User *u);
void cmd_lusers(User *u, char *cmd, int ac, char **av);
void cmd_ping(User *u, char *cmd, int ac, char **av);
void cmd_gen_msg(User *u, char *cmd, int ac, char **av);
/*void cmd_dumpu(User *u, char *cmd, int ac, char **av);*/
void cmd_mode(User *u, char *cmd, int ac, char **av);
void cmd_topic(User *u, char *cmd, int ac, char **av);
void cmd_noop(User *u, char *cmd, int ac, char **av);

#ifdef TOR_DETECT
/* Tor */
int tor_detect(struct in_addr in);
#endif
