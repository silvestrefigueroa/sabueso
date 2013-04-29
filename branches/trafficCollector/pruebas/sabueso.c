//includes del sabueso.c
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <semaphore.h>
#include <pthread.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/stat.h>
//#include <syslog.h>

//MIS PROPIAS CABECERAS
//#include "sabueso.h"
#include "arper.h" //LO SAQUE POR DESUSO Y PARA LIMPIAR UN POCO DE CODIGO
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include "parser.h"

//HANDLERS:
void sigchld_handler(int s){

	sem_t* sem;
	if((sem=sem_open("/semaforo_child", O_RDWR))==SEM_FAILED){
		perror("sem_open()");
		exit(EXIT_FAILURE);
	}
	wait(NULL);
	sem_post(sem);
}

void sigint_handler(int s){
	
	sem_unlink("/semaforo_child");
	
	//ahora hago unlink para la SharedMem

	//if((shm_unlink("/sharedMemPartida"))<0){
	int retorno = shm_unlink("/sharedMemDialogos");
	printf("retorno %d\n",retorno);
	if (retorno < 0 ) {
		perror("shm_unlink()");
		exit(EXIT_FAILURE);

	}
	retorno = shm_unlink("/sharedMemAskers");
	printf("retorno %d\n",retorno);
	if (retorno < 0 ) {
		perror("shm_unlink()");
		exit(EXIT_FAILURE);

	}
	kill(getpid(),SIGTERM);
}

//Aqui comienza la magia =)
int main(int argc, char *argv[]){

	printf("ejecutando el parse...\n");
	sleep(1);
	parse(argv[1]);
	printf("luego de ejecutar el parser... cierro\n");
	return 0;





	int i=0;

	//manejador SIGTERM
	signal(SIGINT , sigint_handler);
	printf("llamar al arper...\n");
//	sleep(2);


/*
for(i=0;i<100000;i++){
	arper("default","default","192.168.1.1","wlan0");//arper crea el frame y lo envia(separar)
}
*/
for(i=0;i<1000000;i++){
	arper("aa:bb:cc:dd:ee:ff","192.168.1.112","192.168.1.1","wlan0");//arper crea el frame y lo envia(separar)
}
	printf("se llamo al arper...\n");


	//fin del programa principal
	//el siguiente sleep va a cambiar por un lazo que corre durante la vida del programa... alli ya no va a haber problema de que temrine el padre..
//	sleep(1000000);//deberia estar en el loop de verificacion de estados o monitoreo de hijos
	write(1,"FIN DEL PROGRAMA PRINCIPAL\n",sizeof("FIN DEL PROGRAMA PRINCIPAL\n"));
	//shm_unlink("./sharedMemPartidas");
	return EXIT_FAILURE;
}//fin del programa
