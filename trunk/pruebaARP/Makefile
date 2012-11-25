CFLAGS= -Wall -g -lpcap


all: pruebaARP
#sabueso: sabueso.o servicio_conn.o funcionHilo.o
sabueso: pruebaARP.o
	$(CC) $(CFLAGS) -o $@ $^ 
clean:
#	rm -fv /dev/shm/sharedMemPartida
	rm -fv *.o
#	rm -fv /dev/shm/sem.semaforo_child
	rm -fv pruebaARP
	rm -fv *~
