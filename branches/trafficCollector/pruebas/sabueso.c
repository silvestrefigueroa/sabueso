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
#include "server2guardStruct.h"




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

//Aqui comienza la magia =)
int main(int argc, char *argv[]){

	printf("ejecutando el parse...\n");
	sleep(1);

//creo una instancia de server2guard (struct) y se la paso al parser, donde el me va a setear en la IP el nombre de la interfaz (dev) y en tos la cantidad de servers2guard (serversQuantity)

	server2guardStruct parametersConf;//aqui voy a recibir la configuracion
	parse(argv[1],&parametersConf,0);

	printf("se recibio del parse: %s\n", parametersConf.ip);


	int serversQuantity=5;//esa cantidad la tiene que levantar de parse 0
	int subindexCounterId=0;

//MEMORIA COMPARTIDA PARA LA TABLA DE SERVERS2GUARD (TRAS OBTENER EL TAMAÑO DESDE EL PARSER MODO 0)

 //INICIA CREACION DE TABLA DE SERVERS2GUARD EN MEMORIA COMPARTIDA

        //Crear zona de memoria compartida para alojar la estructura (o.. array de estructuras)

        //puntero a la memoria compartida
        server2guardStruct *servers2guard_shmPtr=NULL;//le tuve que agregar Struct para mantener el array server2guard que tengo con anterioridad


        //descriptor de la memoria compartida
//      int arpAskers_fdshm;
        int servers2guard_fdshm;

        //sharedMem
        int servers2guardTable_tableSize=serversQuantity;//calculado dinamicamente con anterioridad ;););)
        //malloqueo para el puntero de la shm
//      arpAskers_shmPtr = (arpAsker *)malloc(sizeof(arpAsker)*arpAskersTable_tableSize);
        servers2guard_shmPtr=(server2guardStruct *)malloc(sizeof(server2guardStruct)*servers2guardTable_tableSize);

        server2guardStruct servers2guardTable[servers2guardTable_tableSize];
        //inicializacion:
        for(subindexCounterId=0;subindexCounterId<servers2guardTable_tableSize;subindexCounterId++){
                memset(servers2guardTable[subindexCounterId].mac,0,40);
                memset(servers2guardTable[subindexCounterId].ip,0,40);
                memset(servers2guardTable[subindexCounterId].serverName,0,30);
                servers2guardTable[subindexCounterId].tos=99;//Type of Service
        }//inicializadas las entradas de la tabla, paso a confeccionar la Memoria Compartida


/*
//VOY A SETEAR LA MEMORIA COMPARTIDA CON LOS MISMO DATOS QUE TENGO EN LA ESTRUCTURA (TEMPORAL, SOLO POR DEBUG, LUEGO SE GUARDARA TODO EN LA SHM DE UNA)

        for(subindexCounterId=0;subindexCounterId<servers2guardTable_tableSize;subindexCounterId++){
                strcpy(servers2guardTable[subindexCounterId].mac,_servers2guard[subindexCounterId].mac);
                strcpy(servers2guardTable[subindexCounterId].ip,_servers2guard[subindexCounterId].ip);
                strcpy(servers2guardTable[subindexCounterId].serverName,_servers2guard[subindexCounterId].serverName);
                servers2guardTable[subindexCounterId].tos=_servers2guard[subindexCounterId].tos;//Type of Service
        }
*/




        //SHAREDMEM servers2guardTable
        if(((servers2guard_fdshm=shm_open("/sharedMemServers", O_RDWR|O_CREAT, 0666))<0)){//CONSULTAR: que hace aca?!?!?!?
                perror("shm_open()");
                exit(EXIT_FAILURE);
        }
        //lo escribo en blanco
        if(!(write(servers2guard_fdshm,&servers2guardTable,sizeof(servers2guardTable)))){
        perror("write()");
        exit(EXIT_FAILURE);
        }
        //mmap:
        if(!(servers2guard_shmPtr=mmap(NULL, sizeof(server2guardStruct)*servers2guardTable_tableSize, PROT_READ|PROT_WRITE, MAP_SHARED, servers2guard_fdshm, 0))){
                perror("mmap()");
                exit(EXIT_FAILURE);
        }
        //la truncada de suerte!!:
        ftruncate(servers2guard_fdshm, sizeof(server2guardStruct)*servers2guardTable_tableSize);
        close(servers2guard_fdshm);

        //FINALIZA LA CREACION DE TABLA DE SERVERS2GUARD EN MEMORIA COMPARTIDA

        printf("me quedaron en la shm:\n");

        for(subindexCounterId=0;subindexCounterId<servers2guardTable_tableSize;subindexCounterId++){
                printf("%d ) server=%s ip=%s mac=%s\n",subindexCounterId,servers2guard_shmPtr[subindexCounterId].serverName,servers2guard_shmPtr[subindexCounterId].ip,servers2guard_shmPtr[subindexCounterId].mac);
        }



//FIN MEMORIA COMPARTIDA PARA LA TABLA DE SERVERS2GUARD

	parse(argv[1],1);
	printf("luego de ejecutar el parser... cierro\n");

	return 0;

	write(1,"FIN DEL PROGRAMA PRINCIPAL\n",sizeof("FIN DEL PROGRAMA PRINCIPAL\n"));
	//shm_unlink("./sharedMemPartidas");
	return EXIT_FAILURE;
}//fin del programa


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


