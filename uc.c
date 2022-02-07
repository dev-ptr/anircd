#include "anircd.h"

Chan *clist[128];
User *ulist[128];

int g_numchans = 0, g_numusers = 0;

void uc_init(void)
{
	int	i;

	for (i = 0; i < 128; ++i)
		clist[i] = NULL;
	for (i = 0; i < 128; ++i)
		ulist[i] = NULL;
}

Chan *chan_new(char *name)
{
	Chan	*c;
	char	ch;

	c = (Chan *) malloc(sizeof(Chan));
	if (!c)
	{
		log_error("Failed to allocate Chan struct in %s!", __func__);
		return(NULL);
	}

	c->name = strdup(name);
	c->nusers = 0;
	c->users = NULL;

	ch = (isalpha(name[0])) ? tolower(name[0]) : name[0];

	c->next = clist[(int)ch];
	c->prev = NULL;

	if (clist[(int)ch])
		clist[(int)ch]->prev = c;

	clist[(int)ch] = c;

	++g_numchans;
	return(c);
}

int chan_del(Chan *c)
{
	char	ch;

	if (!c)
	{
		log_error("%s called with null user struct!", __func__);
		return(0);
	}

	if (c->nusers)
	{
		log_error("%s called with users still in-channel! Not deleting channel; check callers.", __func__);
		return(0);
	}

	ch = (isalpha(c->name[0])) ? tolower(c->name[0]) : c->name[0];

	if (c->prev)
		c->prev->next = c->next;
	else
		clist[(int)ch] = c->next;
	if (c->next)
		c->next->prev = c->prev;

	free(c->name);
	/* XXX: Member structs already freed -- we assume we're being called after all users have left. Be sure of caller! */

	free(c);
	--g_numchans;
	return(1);
}

Chan *chan_find(char *name)
{
	Chan	*c;
	char	ch;

	if (!name)
	{
		log_error("%s called with NULL name parameter", __func__);
		return(NULL);
	}

	ch = (isalpha(name[0])) ? tolower(name[0]) : name[0];

	for (c = clist[(int)ch]; c; c = c->next)
		if (!strcasecmp(c->name, name))
			return(c);

	return(NULL);
}

int chan_finduidx(User *u, Chan *c)
{
	int	i;

	for (i = 0; i < c->nusers; ++i)
		if (c->users[i] == u)
			return(i);

	return(-1);
}

int chan_adduent(User *u, Chan *c)
{
	if (!u || !c)
	{
		log_error("NULL u/c parameters passed to %s!", __func__);
		return(0);
	}

	if (chan_finduidx(u, c) >= 0)
	{
		log_error("Duplicate call to %s - user already in channel", __func__);
		return(0);
	}

	if (user_findcidx(u, c) >= 0)
	{
		log_error("Desynchronisation between u/c structs in %s: user not on c->users, but u->chans?!", __func__);
		return(0);
	}

	c->users = (User **) realloc(c->users, ++c->nusers * sizeof(User *));
	c->users[c->nusers - 1] = u;

	u->chans = (Chan **) realloc(u->chans, ++u->nchans * sizeof(Chan *));
	u->chans[u->nchans - 1] = c;

	return(1);
}

int chan_deluent(User *u, Chan *c)
{
	int	idx;

	idx = chan_finduidx(u, c);
	if (idx < 0)
		return(0);

	if (c->nusers == 1)
	{
		free(c->users);
		c->nusers = 0;
		c->users = NULL;
		chan_del(c);
	}
	else
	{
		if (idx != c->nusers - 1)
			memmove(&c->users[idx], &c->users[idx+1], (c->nusers - (idx + 1)) * sizeof(User *));
		c->users = (User **) realloc(c->users, sizeof(User *) * --c->nusers);
	}

	idx = user_findcidx(u, c);
	if (idx < 0)
		return(0);

	if (u->nchans == 1)
	{
		free(u->chans);
		u->nchans = 0;
		u->chans = NULL;
	}
	else
	{
		if (idx != u->nchans - 1)
			memmove(&u->chans[idx], &u->chans[idx+1], (u->nchans - (idx + 1)) * sizeof(Chan *));
		u->chans = (Chan **) realloc(u->chans, sizeof(Chan *) * --u->nchans);
	}

	return(1);
}

User *user_new(int s)
{
	User	*u;

	u = (User *) malloc(sizeof(User));
	if (!u)
	{
		log_error("Failed to allocate new User structure in %s: %s", __func__, strerror(errno));
		return(NULL);
	}

	u->next = ulist[0];
	u->prev = NULL;

	u->s = s;
	u->nick = NULL;
	u->realname = NULL;
	u->host = NULL;
	u->ident = NULL;
	u->signon = 0;	

	u->chans = NULL;
	u->nchans = 0;
	u->flags = 0;
	u->nmcnt = 0;
	
	u->inbuf = u->outbuf = NULL;
	u->inlen = u->outlen = 0;

	if (ulist[0])
		ulist[0]->prev = u;

	ulist[0] = u;

	++g_numusers;
	return(u);
}

void user_move(User *u, char *new)
{
	char	c, c2;

	if (!u)
	{
		log_notice("%s called with NULL user parameter!", __func__);
		return;
	}

	c = isalpha(new[0]) ? tolower(new[0]) : new[0];
	c2 = u->nick ? (isalpha(u->nick[0]) ? tolower(u->nick[0]) : u->nick[0]) : 0;

	if (u->prev)
		u->prev->next = u->next;
	else
		ulist[(int) c2] = u->next;
	if (u->next)
		u->next->prev = u->prev;

	u->next = ulist[(int) c];
	u->prev = NULL;

	if (ulist[(int) c])
		ulist[(int) c]->prev = u;
	ulist[(int) c] = u;
}

int user_del(User *u)
{
	char	c;

	if (!u)
	{
		log_error("%s called with null User struct!", __func__);
		return(0);
	}

	if (u->nchans)
		while (u->chans)
			chan_deluent(u, u->chans[0]);

	c = u->nick ? (isalpha(u->nick[0]) ? tolower(u->nick[0]) : u->nick[0]) : 0;
	if (u->prev)
		u->prev->next = u->next;
	else
		ulist[(int) c] = u->next;

	if (u->next)
		u->next->prev = u->prev;

	if (u->nick)
		free(u->nick);
	if (u->realname)
		free(u->realname);
	if (u->host)
		free(u->host);
	if (u->ident)
		free(u->ident);

	if (u->inbuf)
		free(u->inbuf);
	if (u->outbuf)
		free(u->outbuf);

	free(u);

	--g_numusers;
	return(1);
}

User *user_find(char *nick)
{
	User	*u;
	char	c;

	if (!nick)
	{
		log_error("%s called with NULL nick parameter", __func__);
		return(NULL);
	}

	c = isalpha(nick[0]) ? tolower(nick[0]) : nick[0];
	for (u = ulist[(int) c]; u; u = u->next)
		if (u->nick && !strcasecmp(u->nick, nick))
			return(u);

	return(NULL);
}

int user_findcidx(User *u, Chan *c)
{
	int	i;

	for (i = 0; i < u->nchans; ++i)
		if (u->chans[i] == c)
			return(i);

	return(-1);
}

void user_kill(User *u, char *message)
{
	send_cmd_nobuf(u, NULL, "ERROR :Closing Link: %s (%s)", u->nick ? u->nick : "*", message);
	user_kill2(u, message);
}

void user_kill2(User *u, char *message)
{
	send_ucmd_chanbutone(u, "QUIT :%s", message);
#ifdef SSL_GNUTLS
	gnutls_bye(u->ssl, GNUTLS_SHUT_WR);
	gnutls_db_remove_session(u->ssl);
	gnutls_deinit(u->ssl);
#endif
	close(u->s);
	user_del(u);
}
