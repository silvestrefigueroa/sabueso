#CFLAGS= -Wall -g -lrt
CFLAGS= -Wall -g -lpcap


all: sabueso
#sabueso: sabueso.o servicio_conn.o funcionHilo.o
sabueso: arper.o sabueso.o
	$(CC) -o $@ $^ $(CFLAGS)
#	$(CC) $(CFLAGS) -o $@ $^
clean:
#	rm -fv /dev/shm/sharedMemPartida
	rm -fv *.o
#	rm -fv /dev/shm/sem.semaforo_child
	rm -fv sabueso
	rm -fv *~
