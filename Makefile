CC = gcc

OBJS = arp.o
CFLAGS = -Wall -g

arproxyd: $(OBJS)
	$(CC) -o arproxyd $(OBJS)

.c.o:
	$(CC) $(CFLAGS) -c $*.c

clean:
	rm $(OBJS) arproxyd
