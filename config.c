#include "anircd.h"

static int config_parse(char *line);

char	*c_sname = DEF_SNAME, *c_sdesc = DEF_SDESC, *c_sslkey = DEF_SSLKEY;
int	c_port = DEF_PORT, c_maxusers = DEF_MAXUSERS, c_maxchans = DEF_MAXCHANS;

static Config conftab[] =
{
	{"server_name", CFGTYPE_STRING, {&c_sname}},
	{"server_desc", CFGTYPE_STRING, {&c_sdesc}},
	{"port", CFGTYPE_INT, {&c_port}},
	{"maxusers", CFGTYPE_INT, {&c_maxusers}},
	{"maxchans", CFGTYPE_INT, {&c_maxchans}},
	{"sslkey", CFGTYPE_STRING, {&c_sslkey}},
	{NULL, 0, {NULL}},
};

static int config_parse(char *line)
{
	char	*s;
	Config	*conf;

	if (!line || *line == '#' || !*line)
		return(0);

	s = strchr(line, '=');
	if (!s)
	{
		log_error("Error parsing line '%s' in %s: no '=' detected!", line, __func__);
		return(0);
	}

	*s++ = '\0';
	for (conf = conftab; conf->param; conf++)
	{
		if (!strcasecmp(conf->param, line))
		{
			switch (conf->type)
			{
				case CFGTYPE_STRING:
					*conf->ptr.strptr = strdup(s);
					break;
				case CFGTYPE_INT:
					*conf->ptr.nptr = atoi(s);
					break;
			}
		}
	}

	return(1);
}

int config_load(char *file)
{
	FILE	*fp;
	char	buf[512];

	fp = fopen(file, "r");
	if (!fp)
	{
		log_error("Failed to open '%s' for reading in %s", file, __func__);
		return(0);
	}

	while (!feof(fp))
	{
		fgets(buf, sizeof(buf), fp);
		strip(buf);
		config_parse(buf);
		*buf = '\0';
	}

	fclose(fp);
	return(1);
}
