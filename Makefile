CC?=gcc
LD?=ld
CFLAGS  = -Wall -O2 -g -I/mnt/d/wsl/jpeg-turbo-2.1.4
CFLAGS  += -I/mnt/d/wsl/popt-1.19/src
CFLAGS  += -I/mnt/d/wsl/libevent-2.1.12/include
#LDFLAGS = -L/mnt/d/wsl/jpeg-arm/lib/ -L/mnt/d/wsl/jpeg-am/lib/libjpeg.so -ldl
LDFLAGS = -L/mnt/d/wsl/jpeg-turbo-2.1.4 -lturbojpeg -ldl
LDFLAGS += -L/mnt/d/wsl/libpopt-1.19/src/libs -lpopt
LDFLAGS += -L/mnt/d/wsl/libevent-2.1.12/libs -levent
LDFLAGS +=  -lpthread

all: tjstream_server

tjstream_server: tjstream_server.o
	$(CC) -o $@ $^ $(LDFLAGS)

tjstream_server.o: tjstream_server.c
	$(CC) -c -o $@ $< $(CFLAGS)

clean:
	rm -f tjstream_server tjstream_server.o

.PHONY: all clean
