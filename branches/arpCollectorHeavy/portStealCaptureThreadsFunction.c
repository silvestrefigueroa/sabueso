#include <stdlib.h>
#include "portStealCaptureThreadsArguments.h"
#include "portStealCaptureThreads_pcapCallbackArguments.c"

#define ASKER "192.168.1.100"
#define SERVER2GUARD "192.168.1.1"


//MACROS PARA NOMBRE DE TIPO MUY LARGOS
#define DESCR "((portStealCaptureThreadsArguments *)   argumentos)->descr"
#define FP "((portStealCaptureThreadsArguments *)   argumentos)->fp"
#define NETP "((portStealCaptureThreadsArguments *)   argumentos)->netp"
void *portStealCaptureThreadsFunction(void *argumentos){
	printf("******************************************************************************funcion del hilo psCapturer\n");



	//este hilo captura... y cuanodo detecta una inconsistencia avisa
	//si recibe una señal para detener la captura, se detiene sin mas... (podria usar semaforo para asegurarme que termine el callback)
	
	//PREPARAR CAPTURA:

	//ahora compilo el programa de filtrado para hacer un filtro para ARP

	//quiero capturar todo el trafico con origen el server2guard y destino el asker
	//FILTRO: dst 192.168.1.1 and src 192.168.1.200 (DONDE .1 ES EL SERVER Y .200 EL ASKER POR EJ.)
	//ARMO EL FILTRO CONCATENANDO:

	char filtro[44];//es 43 pero por si le pifie le di uno mas...por el \0

	memset(filtro,0,44);//inicializo

	strcpy(filtro,"dst ");
	strcpy(filtro+strlen(filtro),ASKER);
	strcpy(filtro+strlen(filtro)," and src ");
	strcpy(filtro+strlen(filtro),SERVER2GUARD);

	printf(":::::::::::::::::::::::::::::::::::FILTRO: %s\n",filtro);
	sleep(2);

        if(pcap_compile(((portStealCaptureThreadsArguments *)   argumentos)->descr,&((portStealCaptureThreadsArguments *)   argumentos)->fp,filtro,0,((portStealCaptureThreadsArguments *)   argumentos)->netp)==-1){//luego lo cambiare para filtrar SOLO los mac2guards


                fprintf(stderr,"Error compilando el filtro\n");
                exit(1);
        }
        //Para APLICAR el filtro compilado:
        if(pcap_setfilter(((portStealCaptureThreadsArguments *)   argumentos)->descr,&((portStealCaptureThreadsArguments *)   argumentos)->fp)==-1){
                fprintf(stderr,"Error aplicando el filtro\n");
                exit(1);
        }

//Proceso de captura:
                        puts("\n-------------------------");
                        puts("HILO recolector de tramas ROBADAS...\n");
                        //Argumentos para la funcion callback
                        portSCTA_pcapCallbackArgs conf[2] = {
                        //      {0, "foo",shmPtr,arpAskers_shmPtr},
                                {((portStealCaptureThreadsArguments *)   argumentos)->tableSize, "Argumentos"/*,shmPtr*/}
                        };
                        //El bucle de captura lo armo con variables que el padre ya preparo antes cuando hizo el check de la netmask
                        pcap_loop(((portStealCaptureThreadsArguments *)   argumentos)->descr,-1,(pcap_handler)arpCollector_callback,(u_char*) conf);
                        _exit(EXIT_SUCCESS);
	





	return NULL;
}
