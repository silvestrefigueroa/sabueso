CFLAGS= -Wall -g -lrt -lpthread -lpcap
all: sabueso
sabueso: arper.o splitter.o sabueso.o arpCollector_callback.o
	$(CC) -o $@ $^ $(CFLAGS)
clean:
	rm -fv *.o
	rm -fv sabueso
	rm -fv *~
