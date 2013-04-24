CFLAGS= -Wall -g -lrt -lpthread -lpcap
all: sabueso
sabueso: sabueso.o trafficCollector_callback.o arper.o
	$(CC) -o $@ $^ $(CFLAGS)
clean:
	rm -fv *.o
	rm -fv sabueso
	rm -fv *~
	rm salee
