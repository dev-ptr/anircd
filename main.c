#include "anircd.h"

int g_maxfd = 0;

int main(int ac, char **av)
{
	int		ls, optval = 1, n, i;
	struct		sockaddr_in sin;
	time_t		mclr;
	unsigned char	*buf, mclr_fl;

	/* Ignore SIGPIPE */
	signal(SIGPIPE, SIG_IGN);
	/* For rehashing */
	signal(SIGUSR1, rehash_motd);

	if (!log_init())
	{
		fprintf(stderr, "Failed to open log file; aborting.\n");
		return(-1);
	}

	if (!config_load(CONFIG_FILE))
	{
		fprintf(stderr, "Failed to open config file '%s'; aborting.\n", CONFIG_FILE);
		return(-1);
	}

#ifndef DEBUG
	daemon(1, 0);
#endif

	uc_init();

	ls = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (ls < 0)
	{
		perror("socket");
		return(-1);
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = PF_INET;
	sin.sin_port = htons(c_port);
	sin.sin_addr.s_addr = INADDR_ANY;
#ifdef __FreeBSD__
	sin.sin_len = sizeof(sin);
#endif

	if (setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
	{
		perror("setsockopt");
		exit(-1);
	}

	if (bind(ls, (struct sockaddr *) &sin, sizeof(sin)) < 0)
	{
		perror("bind");
		return(-1);
	}

	if (listen(ls, 5) < 0)
	{
		perror("listen");
		return(-1);
	}

	sock_nonblock(ls);

#ifdef SSL_GNUTLS
	if (!init_SSL(c_sslkey))
		return(-1);
#endif

	load_motd();
	mclr = time(NULL);
	g_maxfd = ls;

	for (;;)
	{
		User	*u, *un;
		struct	timeval tv;
		fd_set	rfds, wfds;

		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		FD_SET(ls, &rfds);
		mclr_fl = 0;

		memset(&tv, 0, sizeof(tv));
		tv.tv_sec = 0;
		tv.tv_usec = 50000;

		if (difftime(time(NULL), mclr) >= 15)
		{
			mclr_fl = 1;
			mclr = time(NULL);
		}

		for (i = 0, g_maxfd = ls; i < 128; ++i)
		{
			for (u = ulist[i]; u; u = u->next)
			{
				if (u->s > g_maxfd)
					g_maxfd = u->s;
				FD_SET(u->s, &rfds);
				u->nmcnt = mclr_fl ? 0 : u->nmcnt;
			}
		}

		if (select(g_maxfd + 1, &rfds, &wfds, NULL, &tv) < 0)
		{
			if (errno == EINTR)
				continue;
			else
			{
				log_error("select() returned an error: %s, exiting", strerror(errno));
				break;
			}
		}

		if (FD_ISSET(ls, &rfds))
		{
			unsigned long	cs;	/* 64-bit fix */
			socklen_t	addrlen = sizeof(sin);

			if ((cs = accept(ls, (struct sockaddr *) &sin, &addrlen)) < 0)
				log_error("accept() failed for client: %s", strerror(errno));
			else if (!sock_nonblock(cs))
				close(cs);
#if defined(TOR_DETECT) && !defined(DEBUG)
			else if (tor_detect(sin.sin_addr))
			{
				char	errbuf[256];

				log_error("Tor detected on IP %s", inet_ntoa(sin.sin_addr));
				snprintf(errbuf, sizeof(errbuf) - 1, ":%s NOTICE AUTH :Your client is running Tor. Tor is prohibited in order to limit ban evasion et al.\r\n", c_sname);
				write(cs, errbuf, strlen(errbuf));
				close(cs);
			}
#endif
			else if (!(u = user_new(cs)))
				close(cs);
#ifdef SSL_GNUTLS
			else
			{
				gnutls_session_t	session;
				int			rc;

				log_error("GNUTLS session init started");
				gnutls_init(&session, GNUTLS_SERVER);
				gnutls_priority_set(session, priority_cache);
				gnutls_credentials_set(session, GNUTLS_CRD_CERTIFICATE, x509_cred);
				gnutls_dh_set_prime_bits(session, DH_BITS);
				gnutls_session_enable_compatibility_mode(session);
				u->ssl = session;
				gnutls_transport_set_ptr(session, (gnutls_transport_ptr_t) cs);

				/* No CA cert */
				gnutls_certificate_send_x509_rdn_sequence(session, 1);
				if ((rc = gnutls_handshake(session)) < 0)
				{
/*					if (rc != GNUTLS_E_AGAIN && rc != GNUTLS_E_INTERRUPTED) */
					if (gnutls_error_is_fatal(rc))
					{
						log_error("gnutls_handshake() returned %d", rc);
						gnutls_bye(session, GNUTLS_SHUT_WR);
						gnutls_db_remove_session(session);
						gnutls_deinit(session);
						user_del(u);
						close(cs);
					}
				}
				else
					u->flags |= UFL_SSLDONE;
			}
#endif
		}

		for (i = 0; i < 128; ++i)
			for (u = ulist[i]; u; u = un)
			{
				/* in case struct gets deleted! */
				un = u->next;
				n = 0;
				if (FD_ISSET(u->s, &rfds) || (u->inbuf && u->inbuf[0]))
					while ((buf = process_read(u, &n)) && n > 0)
					{
						if (process_inbuf(u, (char *) buf) < 0)
						{
							n = -1;
							break;
						}
					}

/*				if (FD_ISSET(u->s, &wfds)) */
				if (n >= 0)
					process_write(u);
			}
	}

	free_motd();

	return(0);
}
