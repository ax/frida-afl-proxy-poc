CC = gcc
CFLAGS = -Wall -Wextra -g
SOME_FLAGS = -ffunction-sections -fdata-sections
#-Werror 

all: fafl-poc

fafl-poc: fafl-poc.c
	$(CC) $(CFLAGS) -I ./include -I ./ -o fafl-poc fafl-poc.c -L. -lfrida-core -lgio-2.0 -lgobject-2.0 -lglib-2.0 -lm -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -lglib-2.0 -zexecstack

vuln-tcp-server: ./vuln-tcp-server.c
	$(CC) $(CFLAGS) -o vuln-tcp-server ./vuln-tcp-server.c

clean:
	rm -f fafl-poc vuln-tcp-server
