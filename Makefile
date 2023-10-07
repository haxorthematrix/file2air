LDFLAGS		= -lorcon -lm 
PROGOBJ		= utils.o crc.o
PROG		= file2air
CFLAGS		= -Wall -ggdb -g3 -pipe

all: file2air 

crc: crc.c crc.h
	$(CC) $(CFLAGS) crc.c -c

utils: utils.c utils.h
	$(CC) $(CFLAGS) utils.c -c

file2air: file2air.c file2air.h $(PROGOBJ)
	$(CC) $(CFLAGS) file2air.c -o file2air $(PROGOBJ) $(LDFLAGS)

clean:
	$(RM) $(PROGOBJ) $(PROG) *~
