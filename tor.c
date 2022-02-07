#include "anircd.h"

#ifdef TOR_DETECT
int tor_detect(struct in_addr in)
{
	struct	hostent	*he;
	char	hostbuf[256];
	unsigned char	*s;
	struct	in_addr	he_i;

	s = (unsigned char *)&in.s_addr;

	snprintf(hostbuf, sizeof(hostbuf) - 1, "%u.%u.%u.%u.tor.ahbl.org", (unsigned int)s[3], (unsigned int)s[2], (unsigned int)s[1], (unsigned int)s[0]);
	he = gethostbyname(hostbuf);
	if (!he)
		return(0);
	memcpy(&he_i.s_addr, he->h_addr_list[0], he->h_length);

	return(he->h_addr_list[0][0] == 0x7F ? 1 : 0);
}
#endif
