#include "anircd.h"

static FILE	*logfp = NULL;
static char	**motd = NULL;
static int	n_motd = 0;

int log_init(void)
{
	logfp = fopen(LOG_FILE, "a+");
	return(logfp ? 1 : 0);
}

void strtoupper(char *s)
{
	char	*p;

	for (p = s; *p; ++p)
		*p = isalpha(*p) ? toupper(*p) : *p;
}

void strip(char *s)
{
	char	*p;

	for (p = s; *p; ++p)
		if (*p == '\n' || *p == '\r')
			*p = '\0';
}

int validate_nick(char *s)
{
	char	*p;

	if (isdigit(*s) || strlen(s) > MAX_NICKLEN)
		return(0);

	for (p = s; *p; ++p)
		if (!isalnum(*p) &&  !(*p == '_' || *p == '\\' || *p == '{' || *p == '}' || *p == '[' || *p == ']'))
			return(0);

	return(1);
}

int validate_chan(char *s)
{
	char	*p;

	if (strlen(s) > MAX_CHANLEN)
		return(0);

	for (p = s; *p; ++p)
		if (!isgraph(*p))
			return(0);

	return(1);
}

int validate_gen(char *s, int fl)
{
	char	*p;

	for (p = s; *p; ++p)
		if ((!isgraph(*p) && (!fl && !isspace(*p))) || (fl && (*p == '@' || *p == '!')))
			return(0);

	return(1);
}

int sock_nonblock(int fd)
{
	int	flags;

	if ((flags = fcntl(fd, F_GETFL)) < 0)
	{
		log_error("Failed to fcntl(fd, F_GETFL) on %d in %s!", fd, __func__);
		return(0);
	}

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
	{
		log_error("Failed to fcntl(fd, F_SETFL) and set non-block for fd %d in %s!", fd, __func__);
		return(0);
	}

	return(1);
}

void load_motd(void)
{
	FILE	*fp;
	char	buf[512];

	fp = fopen(MOTD_FILE, "r");
	if (!fp)
		log_error("MOTD file is missing");
	else
	{
		while (!feof(fp) && !ferror(fp))
		{
			if (!fgets(buf, sizeof(buf), fp))
				break;
			motd = (char **) realloc(motd, sizeof(char *) * ++n_motd);
			if (!motd)
			{
				log_error("realloc() failed in %s", __FUNCTION__);
				n_motd = 0;
				motd = NULL;
				break;
			}
			strip(buf);
			motd[n_motd - 1] = strdup(buf);
		}

		log_notice("MOTD loaded from %s, %d lines", MOTD_FILE, n_motd);
		fclose(fp);
	}
}

void free_motd(void)
{
	int	i;

	if (motd)
	{
		for (i = 0; i < n_motd; ++i)
			free(motd[i]);
		free(motd);
	}
	motd = NULL;
	n_motd = 0;
}

void rehash_motd(int unused)
{
	log_notice("Rehashing MOTD (received SIGUSR1)");
	free_motd();
	load_motd();
}

void send_motd(User *u)
{
	int	i;

	if (!n_motd)
		send_num(u, ERR_NOMOTD, NULL, ":MOTD file is missing");
	else
	{
		send_num(u, RPL_MOTDSTART, NULL, ":- %s Message of the Day -", c_sname);
		for (i = 0; i < n_motd; ++i)
			send_num(u, RPL_MOTD, NULL, ":- %s", motd[i]);
	}
	send_num(u, RPL_ENDOFMOTD, NULL, ":End of /MOTD command");
}

void send_cmd(User *u, char *prefix, char *fmt, ...)
{
	va_list	ap;
	char	buf[512], buf2[1024];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (prefix)
		snprintf(buf2, sizeof(buf2), ":%s %s\r\n", prefix, buf);
	else
		snprintf(buf2, sizeof(buf2), "%s\r\n", buf);

	send_buf(u, buf2);
}

void send_cmd_nobuf(User *u, char *prefix, char *fmt, ...)
{
	va_list	ap;
	char	buf[512], buf2[1024];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	if (prefix)
		snprintf(buf2, sizeof(buf2), ":%s %s\r\n", prefix, buf);
	else
		snprintf(buf2, sizeof(buf2), "%s\r\n", buf);

	/* attempt immediate write -- may not succeed, but only used in user_kill() et al */
#ifdef SSL_GNUTLS
	gnutls_record_send(u->ssl, buf2, strlen(buf2));
#else
	write(u->s, buf2, strlen(buf2));
#endif
}

int send_ucmd_chanbutone(User *u, char *fmt, ...)
{
	User	*ut;
	Chan	*c;
	int	i, j;
	va_list	ap;
	char	buf[512], buf2[1024];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	snprintf(buf2, sizeof(buf2), ":%s!%s@%s %s\r\n", u->nick, u->ident, u->host, buf);

	for (i = 0; i < u->nchans; ++i)
	{
		c = u->chans[i];
		for (j = 0; j < c->nusers; ++j)
		{
			ut = c->users[j];
			if (ut != u)
				send_buf(ut, buf2);
		}
	}

	return(1);
}

int send_ucmd_one(User *from, User *to, char *fmt, ...)
{
	va_list	ap;
	char	buf[512], buf2[1024];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	snprintf(buf2, sizeof(buf2), ":%s!%s@%s %s\r\n", from->nick, from->ident, from->host, buf);

	send_buf(to, buf2);
	return(1);
}

int send_ucmd_schanbutone(User *u, Chan *c, char *fmt, ...)
{
	User	*ut;
	int	i;
	va_list	ap;
	char	buf[512], buf2[1024];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	snprintf(buf2, sizeof(buf2), ":%s!%s@%s %s\r\n", u->nick, u->ident, u->host, buf);

	for (i = 0; i < c->nusers; ++i)
	{
		ut = c->users[i];
		if (ut != u)
			send_buf(ut, buf2);
	}

	return(1);
}

int send_ucmd_schan(User *u, Chan *c, char *fmt, ...)
{
	User	*ut;
	int	i;
	va_list	ap;
	char	buf[512], buf2[1024];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	snprintf(buf2, sizeof(buf2), ":%s!%s@%s %s\r\n", u->nick, u->ident, u->host, buf);

	for (i = 0; i < c->nusers; ++i)
	{
		ut = c->users[i];
		send_buf(ut, buf2);
	}

	return(1);
}

void snotice(User *u, char *fmt, ...)
{
	va_list	ap;
	char	buf[512], buf2[1024];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	snprintf(buf2, sizeof(buf2), ":%s NOTICE %s :%s\r\n", c_sname, u->nick, buf);

	send_buf(u, buf2);
}

void send_num(User *u, int num, char *cmd, char *fmt, ...)
{
	va_list ap;
	char	buf[512], buf2[1024];

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (cmd)
		snprintf(buf2, sizeof(buf2), ":%s %03d %s %s %s\r\n", c_sname, num, u->nick ? u->nick : "*", cmd, buf);
	else
		snprintf(buf2, sizeof(buf2), ":%s %03d %s %s\r\n", c_sname, num, u->nick ? u->nick : "*", buf);

	send_buf(u, buf2);
}

void send_buf(User *u, char *buf)
{
	int	outq, fl, len;

	if (!u || !buf)
	{
		log_error("NULL pointer passed to %s!", __func__);
		return;
	}

	outq = ((strlen(buf) / 1024) + 1) * 1024;
	fl = (!u->outbuf) ? 1 : 0;
	outq += fl ? 0 : ((strlen((char *) u->outbuf) / 1024) + 1) * 1024;

	if ((u->outlen < MAX_UOBUF && u->outlen < outq) || fl)
	{
		u->outlen = outq > MAX_UOBUF ? MAX_UOBUF : outq;
		if (!(u->outbuf = (unsigned char *) realloc((void *) u->outbuf, u->outlen)))
		{
			log_error("Failed to realloc() u->outbuf in %s!", __func__);
			return;
		}
		if (fl)
			*u->outbuf = '\0';
	}

	len = strlen((char *) u->outbuf);
	if (len <= u->outlen - 2)
		strncat((char *) u->outbuf, buf, u->outlen - strlen((char *) u->outbuf) - 2);
}

int log_error(char *s, ...)
{
	va_list		ap;
	char		buf[4096];
	char		date[128];
	time_t		now;
	struct tm	*tm;

	if (!logfp)
		return(0);

	now = time(NULL);
	tm = localtime(&now);
	if (!tm)
		return(0);

	strftime(date, sizeof(date), "%a %b %d %T %Y", tm);
	va_start(ap, s);
	vsnprintf(buf, sizeof(buf), s, ap);
	va_end(ap);

	fprintf(logfp, "[%s] %s\n", date, buf);
	if (ferror(logfp))
	{
		fclose(logfp);
		logfp = NULL;
		return(0);
	}

	fflush(logfp);
	return(1);
}
