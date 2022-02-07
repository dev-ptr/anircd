# Requires GNUTLS installed.

CC = gcc
#CFLAGS = -std=gnu99 -Wall -Werror -I/usr/local/include -DSSL_GNUTLS -lgnutls -Os -s -lgcrypt #SSL
CFLAGS = -std=gnu99 -Wall -Werror -I/usr/local/include-lgnutls -Os -s -lgcrypt
#CFLAGS = -std=gnu99 -Wall -Werror -I/usr/local/include -ggdb
#CFLAGS = -std=gnu99 -Wall -Werror -Os -s
#LDFLAGS = -L/usr/local/lib -lssl 
#LDFLAGS = `libgnutls-config --libs`
#LDFLAGS = 
OBJS = command.o config.o main.o process.o ssl.o uc.o util.o tor.o

all: anircd

anircd: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) -o $@
.c.o:
	$(CC) $(CFLAGS) $? -c -o $@

clean:
	rm -f anircd *.o
