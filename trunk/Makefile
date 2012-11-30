CFLAGS= -Wall -g -lrt -lpcap
all: sabueso
sabueso: arper.o parser.o sabueso.o
	$(CC) -o $@ $^ $(CFLAGS)
clean:
	rm -fv *.o
	rm -fv sabueso
	rm -fv *~
