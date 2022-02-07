#include "anircd.h"

void cmd_register(User *u)
{
	u->flags |= UFL_REG;

	/* XXX: configurable 'network' variable */
	send_num(u, 1, NULL, ":Welcome to the Anarchy IRC Network %s!%s@%s", u->nick, u->ident, u->host);
	send_num(u, 2, NULL, ":Your host is %s, running version AnarchyIRCd", c_sname);
	send_num(u, 3, NULL, ":This server was created Wed Jul 5 2006 at 00:00:00 UTC");
	send_num(u, 4, NULL, "%s AnarchyIRCd", c_sname);

	cmd_do_lusers(u);
	send_motd(u);
}

void cmd_user(User *u, char *cmd, int ac, char **av)
{
	if (ac < 4)
	{
		send_num(u, ERR_NEEDMOREPARAMS, cmd, ":Not enough parameters");
		return;
	}

	if (strlen(av[3]) > MAX_REALNAME || strlen(av[0]) > MAX_IDENT || !validate_gen(av[0], 1) || !validate_gen(av[3], 0))
		send_num(u, ERR_NEEDMOREPARAMS, cmd, ":Not enough parameters");
	else
	{
		u->host = strdup("no.host");
		u->realname = strdup(av[3]);
		u->ident = strdup(av[0]);
		u->flags |= UFL_HAVEUSER;
	}
}

void cmd_nick(User *u, char *cmd, int ac, char **av)
{
	if (ac < 1 || strlen(av[0]) < 1)
	{
		send_num(u, ERR_NONICKNAMEGIVEN, NULL, ":No nickname given");
		return;
	}

	if (!validate_nick(av[0]))
		send_num(u, ERR_ERRONEOUSNICKNAME, av[0], ":Erroneous nickname");
	else if (user_find(av[0]))
		send_num(u, ERR_NICKNAMEINUSE, av[0], ":Nickname is already in use");
	else
	{
		if (u->flags & UFL_REG)
		{
			send_ucmd_chanbutone(u, "NICK :%s", av[0]);
			send_ucmd_one(u, u, "NICK :%s", av[0]);
		}
		user_move(u, av[0]);
		if (u->nick)
			free(u->nick);
		u->nick = strdup(av[0]);
		if (!(u->flags & UFL_HAVENICK))
			u->flags |= UFL_HAVENICK;
	}
}

void cmd_quit(User *u, char *cmd, int ac, char **av)
{
	char	reason[MAX_QUIT];

	snprintf(reason, sizeof(reason), "Quit: %s", ac >= 1 ? av[0] : "");
	user_kill(u, reason);
}

void cmd_names(User *u, char *cmd, int ac, char **av)
{
	if (ac < 1)
		send_num(u, RPL_ENDOFNAMES, "*", ":End of /NAMES list");
	else
	{
		Chan	*c;

		c = chan_find(av[0]);
		if (!c || chan_finduidx(u, c) < 0)
			send_num(u, ERR_NOSUCHCHANNEL, av[0], ":No such channel");
		else
			cmd_do_names(u, c);
	}
}

void cmd_do_names(User *u, Chan *c)
{
	int	i;
	char	nbuf[300];

	*nbuf = '\0';
	for (i = 0; i < c->nusers; ++i)
	{
		strncat(nbuf, c->users[i]->nick, sizeof(nbuf) - strlen(nbuf) - 1);
		strncat(nbuf, " ", sizeof(nbuf) - strlen(nbuf) - 1);
		if (strlen(nbuf) >= 256)
		{
			send_num(u, RPL_NAMREPLY, "=", "%s :%s", c->name, nbuf);
			*nbuf = '\0';
		}
	}
	if (*nbuf)
		send_num(u, RPL_NAMREPLY, "=", "%s :%s", c->name, nbuf);

	send_num(u, RPL_ENDOFNAMES, c->name, ":End of /NAMES list");
}

void cmd_join(User *u, char *cmd, int ac, char **av)
{
	char	**chav, *s, *t;
	int	chac, i;
	Chan	*c;

	if (ac < 1)
	{
		send_num(u, ERR_NEEDMOREPARAMS, cmd, ":Not enough parameters");
		return;
	}

	for (chac = 0, chav = NULL, s = av[0]; ; s = t)
	{
		chav = (char **) realloc(chav, sizeof(char *) * ++chac);
		chav[chac - 1] = s;
		if ((t = strchr(s, ',')))
			*t++ = (char) 0;
		else
			break;
	}

	for (i = 0; i < chac; ++i)
		if (!strcasecmp(chav[i], "0"))
		{
			int	j;

			for (j = 0; u->nchans; ++j)
			{
				send_ucmd_schan(u, u->chans[j], "PART :%s", u->chans[0]->name);
				chan_deluent(u, u->chans[0]);
			}
		}
		else if (!IsChan(chav[i]))
			send_num(u, ERR_NOSUCHCHANNEL, chav[i], ":No such channel");
		else
		{
			if (u->nchans > MAX_CHANS)
			{
				send_num(u, ERR_TOOMANYCHANNELS, chav[i], ":You have joined too many channels");
				continue;
			}

			if (!validate_chan(chav[i]))
			{
				send_num(u, ERR_NOSUCHCHANNEL, chav[i], ":Illegal channel name specified");
				continue;
			}

			c = chan_find(chav[i]);
			if (!c)
				c = chan_new(chav[i]);
			/* Already on channel */
			if (user_findcidx(u, c) >= 0)
				continue;

			chan_adduent(u, c);
			send_ucmd_schan(u, c, "JOIN :%s", c->name);
			cmd_do_names(u, c);
			send_num(u, RPL_CHANNELMODEIS, c->name, "+nt");
		}

	free(chav);
}

void cmd_part(User *u, char *cmd, int ac, char **av)
{
	char	**chav, *s, *t;
	int	chac, i;
	Chan	*c;

	if (ac < 1)
	{
		send_num(u, ERR_NEEDMOREPARAMS, cmd, ":Not enough parameters");
		return;
	}

	for (chac = 0, chav = NULL, s = av[0]; ; s = t)
	{
		chav = (char **) realloc(chav, sizeof(char *) * ++chac);
		chav[chac - 1] = s;
		if ((t = strchr(s, ',')))
			*t++ = (char) 0;
		else
			break;
	}

	for (i = 0; i < chac; ++i)
		if (!IsChan(chav[i]))
			send_num(u, ERR_NOSUCHCHANNEL, chav[i], ":No such channel");
		else
		{
			c = chan_find(chav[i]);
			if (!c)
				send_num(u, ERR_NOSUCHCHANNEL, chav[i], ":No such channel");
			else if (user_findcidx(u, c) < 0)
				send_num(u, ERR_NOTONCHANNEL, chav[i], ":You're not on that channel");
			else
			{
				send_ucmd_schan(u, c, "PART :%s", c->name);
				chan_deluent(u, c);
			}
		}

	free(chav);
}

void cmd_gen_msg(User *u, char *cmd, int ac, char **av)
{
	char	**tav, *s, *t;
	int	tac, i;

	u->nmcnt++;

	if (ac < 1)
		send_num(u, ERR_NORECIPIENT, NULL, ":No recipient given (%s)", cmd);
	else if (ac < 2 || !*av[1])
		send_num(u, ERR_NOTEXTTOSEND, NULL, ":No text to send");
	else
	{
		for (tac = 0, tav = NULL, s = av[0]; ; s = t)
		{
			tav = (char **) realloc(tav, sizeof(char *) * ++tac);
			tav[tac - 1] = s;
			if ((t = strchr(s, ',')))
				*t++ = (char) 0;
			else
				break;
		}

		for (i = 0; i < tac; ++i)
			if (IsChan(tav[i]))
			{
				Chan	*c;

				c = chan_find(tav[i]);
				if (!c)
				{
					send_num(u, ERR_NOSUCHNICK, tav[i], ":No such nick/channel");
					continue;
				}
				if (user_findcidx(u, c) < 0)
				{
					send_num(u, ERR_CANNOTSENDTOCHAN, tav[i], ":Cannot send to channel");
					continue;
				}

				send_ucmd_schanbutone(u, c, "%s %s :%s", cmd, tav[i], av[1]);
			}
			else
			{
				User *ut;

				ut = user_find(tav[i]);
				if (!ut)
				{
					send_num(u, ERR_NOSUCHNICK, tav[i], ":No such nick/channel");
					continue;
				}
				send_ucmd_one(u, ut, "%s %s :%s", cmd, tav[i], av[1]);
			}

		free(tav);
	}
}

void cmd_do_lusers(User *u)
{
	send_num(u, RPL_LUSERCLIENT, NULL, ":There are %d users and 0 invisible users on 1 servers", g_numusers);
	send_num(u, RPL_LUSEROP, NULL, "0 :operator(s) online");
	send_num(u, RPL_LUSERCHANNELS, NULL, "%d :channels formed", g_numchans);
	send_num(u, RPL_LUSERME, NULL, ":I have %d clients and 0 servers", g_numusers);
	send_num(u, 265, NULL, ":Current Local Users: %d  Max: -1", g_numusers);
	send_num(u, 266, NULL, ":Current Global Users: %d  Max: -1", g_numusers);
}

void cmd_lusers(User *u, char *cmd, int ac, char **av)
{
	cmd_do_lusers(u);
}

void cmd_ping(User *u, char *cmd, int ac, char **av)
{
	if (ac < 1)
		send_num(u, ERR_NOORIGIN, NULL, ":No origin specified");
	else
		send_cmd(u, c_sname, "PONG %s :%s", c_sname, av[0]);
}

void cmd_noop(User *u, char *cmd, int ac, char **av)
{
}

void cmd_mode(User *u, char *cmd, int ac, char **av)
{
	if (ac < 1)
		send_num(u, ERR_NEEDMOREPARAMS, "MODE", ":Not enough parameters");
	else
	{
		if (!strcasecmp(av[0], u->nick))
			send_num(u, RPL_UMODEIS, NULL, "+i");
		else if (IsChan(av[0]) && chan_find(av[0]))
			send_num(u, RPL_CHANNELMODEIS, av[0], "+nt");
		else
			send_num(u, ERR_NOSUCHCHANNEL, av[0], ":No such channel");
	}
}

void cmd_topic(User *u, char *cmd, int ac, char **av)
{
	if (ac < 1)
		send_num(u, ERR_NEEDMOREPARAMS, "MODE", ":Not enough parameters");
	else
	{
		if (!IsChan(av[0]) || !chan_find(av[0]))
			send_num(u, ERR_NOSUCHCHANNEL, av[0], ":No such channel");
		else
			send_num(u, RPL_NOTOPIC, av[0], ":No topic is set");
	}
}

/*
void cmd_whois(User *u, char *cmd, int ac, char **av)
{
	User	*u;

	if (ac < 1)
		send_num(u, 409, 
	send_num(u, 409, 
}
*/
