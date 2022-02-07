#include "anircd.h"

#ifdef SSL_GNUTLS
static unsigned char *process_ssl_accept(User *u, int *n)
{
	int	rc;

	if ((rc = gnutls_handshake(u->ssl)) < 0)
	{
		if (rc != GNUTLS_E_AGAIN && rc != GNUTLS_E_INTERRUPTED)
		{
			log_error("process_ssl_accept(): gnutls_handshake() returned %d", rc);
			user_kill2(u, "SSL negotiation failed");
			*n = -1;
			return(NULL);
		}
	}
	else
	{
		u->flags |= UFL_SSLDONE;
		send_cmd(u, NULL, "PING :BROKEN-mIRC-SSL");
	}

	*n = 1;

	return(NULL);
}
#endif

unsigned char *process_read(User *u, int *n)
{
	int	len;
	unsigned char	*in, *s, *dup;
	int	inq, fl;
	unsigned int	err, err_len;

	if (!u)
	{
		log_error("process_read() called with NULL user struct!");
		*n = -1;
		return(NULL);
	}

	/* to catch socket errors earlier */
	err_len = sizeof(err);
	if (getsockopt(u->s, SOL_SOCKET, SO_ERROR, &err, &err_len) < 0)
	{
		log_error("getsockopt() failed on user %s[%d]!", u->nick ? u->nick : "(unknown)", u->s);
		*n = -1;
		return(NULL);
	}

	if (err && err != EAGAIN && err != EINTR)
	{
		log_error("Error while reading from socket %d: %d[%s]", u->s, err, strerror(err));
		user_kill2(u, "Socket error while reading socket");
		*n = -1;
		return(NULL);
	}

#ifdef SSL_GNUTLS
	if (!(u->flags & UFL_SSLDONE))
		return(process_ssl_accept(u, n));
	inq = 0;
#else
	if (ioctl(u->s, FIONREAD, &inq) < 0)
		log_error("ioctl(%d, FIONREAD) failed: %d[%s]", u->s, errno, strerror(errno));
#endif

#if 0
	log_error("inq=%d for user %s[%d]", inq, u->nick?u->nick:"(unknown)", u->s);
#endif

	inq = ((inq / 1024) + 1) * 1024;

	fl = (!u->inbuf) ? 1 : 0;
	if ((u->inlen < MAX_UINBUF && u->inlen < inq) || fl)
	{
		u->inlen = inq > MAX_UINBUF ? MAX_UINBUF : inq;
		u->inbuf = (unsigned char *) realloc((void *) u->inbuf, u->inlen);
		if (!u->inbuf)
		{
			log_error("Failed to allocate memory for u->inbuf in %s!");
			return(NULL);
		}
		if (fl)
			*u->inbuf = '\0';
	}

	len = strlen((char *) u->inbuf);
	if (len <= u->inlen - 2)
	{
		in = u->inbuf + len; 
#ifdef SSL_GNUTLS
		*n = gnutls_record_recv(u->ssl, in, u->inlen - len - 2);
#else
		*n = read(u->s, in, u->inlen - len - 2);
#endif
		if (*n > 0)
			u->inbuf[*n + len] = '\0';

#ifdef SSL_GNUTLS
		if ((*n < 0 && *n != GNUTLS_E_INTERRUPTED && *n != GNUTLS_E_AGAIN) || !*n)
#else
		if ((*n < 0 && errno != EAGAIN && errno != EINTR) || !*n)
#endif
		{
#ifdef SSL_GNUTLS
			log_error("Error while reading from socket %d: %d", u->s, *n);
#else
			log_error("Error while reading from socket %d: %d[%s], n=%d", u->s, errno, strerror(errno), *n);
			errno = 0;
#endif
			user_kill2(u, "Socket error while reading socket");
			*n = !(*n) ? -1 : *n;
			return(NULL);
		}
	}

	s = (unsigned char *) strchr((char *) u->inbuf, '\n');
	if (!s)
		return(NULL);

	*s++ = '\0';
	dup = (unsigned char *) strdup((char *) u->inbuf);
	memmove(u->inbuf, s, strlen((char *) s) + 1);

	*n = 1;
#ifdef DEBUG
	log_error("User %s[%d]: dup=%s, inbuf=%s\n", u->nick?u->nick:"(unknown)", u->s, dup, u->inbuf);
#endif
	return(dup);
}

int process_write(User *u)
{
	int	n = 0;

	if (!u->outbuf)
		return(1);

#ifdef SSL_GNUTLS
	if ((n = gnutls_record_send(u->ssl, u->outbuf, strlen((char *) u->outbuf))) < 0 && n != GNUTLS_E_INTERRUPTED && n != GNUTLS_E_AGAIN)
#else
	if ((n = write(u->s, u->outbuf, strlen((char *) u->outbuf))) < 0 && errno != EAGAIN && errno != EINTR)
#endif
	{
#ifdef SSL_GNUTLS
		log_error("Error while writing to socket %d: GNUTLS[%d]", u->s, n);
#else
		log_error("Error while writing to socket %d: %d[%s]", u->s, errno, strerror(errno));
#endif
		return(0);
	}

	if (n > 0)
	{
		if (n < strlen((char *) u->outbuf))
			memmove(u->outbuf, u->outbuf + n, strlen((char *) u->outbuf) - n + 1);
		else
		{
			free(u->outbuf);
			u->outbuf = NULL;
			u->outlen = 0;
		}
	}

	return(1);
}

int process_inbuf(User *u, char *buf)
{
	int	ac, rc = 0;
	char	**av, *source, *cmd, *s, *t;

	strip((char *) buf);

	for (ac = 0, av = NULL, s = ((*buf == ':') ? buf + 1 : buf); ; s = t)
	{
		av = (char **) realloc(av, sizeof(char *) * ++ac);
		av[ac - 1] = (*s != ':') ? s : s + 1;
		if (!(t = strchr(s, ' ')) || *s == ':')
			break;
		*t = '\0';
		while (isspace(*++t));
	}
	source = (*buf == ':') ? av[0] : NULL;
	cmd = source ? av[1] : av[0];
	ac -= source ? 2 : 1;
	av += source ? 2 : 1;

	strtoupper(cmd);

	if (source)
	{
		s = strchr(source, '!');
		if (s)
			*s = '\0';
	}

#ifndef DEBUG
	if (u->nmcnt > MAX_MSG)
	{
		user_kill(u, "Excess flood");
		rc = -1;
		goto out;
	}
#endif

	/* 'source' is not used as the user context is already known */
	if (!(u->flags & UFL_REG))
	{
		if (!strcasecmp(cmd, "USER"))
			cmd_user(u, cmd, ac, av);
		else if (!strcasecmp(cmd, "NICK"))
			cmd_nick(u, cmd, ac, av);
/*		else if (!strcasecmp(cmd, "PONG"))
			cmd_pong(u, cmd, ac, av);
		else if (!strcasecmp(cmd, "ADMIN"))
			cmd_admin(u, cmd, ac, av);*/
		else if (!strcasecmp(cmd, "QUIT"))
		{
			cmd_quit(u, cmd, ac, av);
			rc = -1;
			goto out;
		}

		else if (!strcasecmp(cmd, "PONG"))
			cmd_noop(u, cmd, ac, av);
		else
			send_num(u, 451, cmd, ":You have not registered");	

		if ((u->flags & (UFL_HAVEUSER|UFL_HAVENICK)) == (UFL_HAVEUSER|UFL_HAVENICK))
			cmd_register(u);
	}
	else
	{
		if (!strcasecmp(cmd, "QUIT"))
		{
			cmd_quit(u, cmd, ac, av);
			rc = -1;
			goto out;
		}
		else if (!strcasecmp(cmd, "NAMES"))
			cmd_names(u, cmd, ac, av);
		else if (!strcasecmp(cmd, "JOIN"))
			cmd_join(u, cmd, ac, av);
		else if (!strcasecmp(cmd, "PRIVMSG"))
			cmd_gen_msg(u, cmd, ac, av);
		else if (!strcasecmp(cmd, "NICK"))
			cmd_nick(u, cmd, ac, av);
		else if (!strcasecmp(cmd, "PART"))
			cmd_part(u, cmd, ac, av);
		else if (!strcasecmp(cmd, "LUSERS"))
			cmd_lusers(u, cmd, ac, av);
		else if (!strcasecmp(cmd, "NOTICE"))
			cmd_gen_msg(u, cmd, ac, av);
		else if (!strcasecmp(cmd, "PING"))
			cmd_ping(u, cmd, ac, av);
		else if (!strcasecmp(cmd, "PONG"))
			cmd_noop(u, cmd, ac, av);
		else if (!strcasecmp(cmd, "MOTD"))
			send_motd(u);
		else if (!strcasecmp(cmd, "MODE"))
			cmd_mode(u, cmd, ac, av);
		else if (!strcasecmp(cmd, "TOPIC"))
			cmd_topic(u, cmd, ac, av);
/*		else if (!strcasecmp(cmd, "WHOIS"))
			cmd_whois(u, cmd, ac, av);*/
	}

/*	*u->inbuf = '\0'; */
out:
	free(source ? av - 2 : av - 1);
	free(buf);
	return(rc);
}
