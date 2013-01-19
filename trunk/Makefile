CFLAGS= -Wall -g -lrt -lpcap -lpthread
all: sabueso
sabueso: arper.o parser.o sabueso.o arpCollector_callback.o
	$(CC) -o $@ $^ $(CFLAGS)
clean:
	rm -fv *.o
	rm -fv sabueso
	rm -fv *~
