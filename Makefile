CFLAGS+=-Wall
keeprelocs: keeprelocs.c

clean:
	rm -f *.o keeprelocs

.PHONY: clean
