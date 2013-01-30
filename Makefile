CFLAGS= -Wall -g -lrt -lpthread -lpcap
all: sabueso
sabueso: arper.o parser.o sabueso.o arpCollector_callback.o arpDialoguesTableManager.o
	$(CC) -o $@ $^ $(CFLAGS)
clean:
	rm -fv *.o
	rm -fv sabueso
	rm -fv *~
