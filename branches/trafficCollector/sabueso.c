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
#include "arper.h" //LO SAQUE POR DESUSO Y PARA LIMPIAR UN POCO DE CODIGO
#include "parser.h"
#include "arpDialogStruct.h"
#include "trafficCollector_callback.h"
#include "callbackArgs.h"
#include "networkSizer.h"
#include "pstFunction.h"

//MENSAJES ESTATICOS
#define MSG_START "Comienza aqui el programa principal\n"

//MACROS DE ARGS
#define TABLE_SIZE 4

//Icludes del trafficCollector.c
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











//SABUESO STARTS HERE!!!


int main(int argc, char *argv[]){

	//manejador SIGTERM
	signal(SIGINT , sigint_handler);

	if(0>=write(1,MSG_START, strlen(MSG_START)))
		return -1;


	int i=0;//indice utilizando en los for...


	printf("ejecutando el parse...\n");
        sleep(1);

	//Le paso al parser una estructura server2guard para que me devuelva los parametros =)
	//EN LA IP ME VA A DEVOLVER LA NIC
	//EN EL TOS ME DEVUELVE EL SERVERQUANTITY
	//

        server2guardStruct parametersConf;//aqui voy a recibir la configuracion
        memset(parametersConf.ip,0,40);
        memset(parametersConf.mac,0,40);
        parametersConf.tos=0;
	parametersConf.pstlRepeatLimit=0;
	parametersConf.pstlPoolingTime=0;
	parametersConf.pstlSleepTime=0;



        parse(argv[1],&parametersConf,0);

        printf("se recibio del parse: NIC: %s serversQuantity: %d\n", parametersConf.nic, parametersConf.serversQuantity);
	printf("tambien parametros del pst: pstlRepeatLimit= %d, pstlPoolingTime= %d, pstlSleepTime=%d \n", parametersConf.pstlRepeatLimit,parametersConf.pstlPoolingTime,parametersConf.pstlSleepTime);

	printf("\n\n\n");
	printf("-------------------------------------------------------------------------------------------------------------------------------------------------------\n");
	printf("FINALIZADA LA CARGA DE PARAMETROS COMIENZA EL LANZAMIENTO DEL PROGRAMA PRINCIPAL...\n");
	printf("-------------------------------------------------------------------------------------------------------------------------------------------------------\n");
	sleep(2);

//------------INICIA ZONA DE CONTROL DE PARAMETROS DE APLICACION-----------------------------------------------//
	//PARAMETROS DE LANZAMIENTO:

	int serversQuantity=0;
	serversQuantity = parametersConf.serversQuantity;//cantidad de servers a cuidar

	server2guardStruct servers2guardConf[serversQuantity];//creo las estructuras para los servers2guard (luego van a parar a la shm)


	//PARAMETROS DEL PORT STEALER:

	int pstlRepeatLimit=parametersConf.pstlRepeatLimit;
	int pstlPoolingTime=parametersConf.pstlPoolingTime;
	int pstlSleepTime=parametersConf.pstlSleepTime;


	//INICIALIZAR:

	for(i=0;i<serversQuantity;i++){
		memset(servers2guardConf[i].ip,0,40);
		memset(servers2guardConf[i].mac,0,40);
		memset(servers2guardConf[i].serverName,0,30);
		servers2guardConf[i].tos=99;
	}


	parse(argv[1],&servers2guardConf,1);

	printf("\n\n\n\n\n\n\n\n\n\n\n");

	printf("Mostrando configuracion leida:\n");

	for(i=0;i<serversQuantity;i++){
		printf("server.ip: %s \n",servers2guardConf[i].ip);
		printf("server.mac: %s \n",servers2guardConf[i].mac);
		printf("server.serverName: %s \n",servers2guardConf[i].serverName);
		printf("server.tos: %d \n",servers2guardConf[i].tos);
	}


	printf("---------------------------------------------------------------\n\n");


	int j=0;//otro subindice
	int c=0;
	int live=0;


//	serversQuantity=1;//PARA DEBUGGEAR CON UN SOLO HIJO.. SINO SE ENSUCIA MUCHISIMO EL STDOUT



	//PARAMETROS DE CAPTURA, DE PASO PREAPRA VARIABLES DE CAPTURA PARA EL PRIMER HIJO
	//COmienza a preparar la captura...
	char *dev=NULL;
	char *net=NULL;
	char *mask=NULL;
	struct in_addr addr;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* descr;//descriptor de la captura
	struct bpf_program fp;//aca se guardara el programa compilado de filtrado
	bpf_u_int32 maskp;// mascara de subred
	bpf_u_int32 netp;// direccion de red

/*
	cdev = pcap_lookupdev(errbuf); //Buscamos un dispositivo del que comenzar la captura
	printf("\nEcontro como dispositivo %s\n",dev);
	if (dev == NULL){
		fprintf(stderr," %s\n",errbuf); exit(1);
	}
	else{
		printf("Abriendo %s en modo promiscuo\n",dev);
	}
*/

	dev = parametersConf.nic;//no utiliza la que detecta automaticamente sino que usa la de la config

	//obtener la direccion de red y la netmask de la NIC en "dev"
	if(pcap_lookupnet(dev,&netp,&maskp,errbuf)==-1){
		printf("ERROR %s\n",errbuf);
		exit(-1);
	}
	addr.s_addr = netp; //traducir direccion de red en algo legible
	if((net = inet_ntoa(addr))==NULL){
		perror("inet _ntoa");
		exit(-1);
	}
	printf("Direccion de Red: %s\n",net);
	addr.s_addr = maskp;
	mask = inet_ntoa(addr);
	if((net=inet_ntoa(addr))==NULL){
		perror("inet _ntoa");
		exit(-1);
	}
	printf("Mascara de Red: %s\n",mask);
	//comenzar captura y obtener descriptor llamado "descr" del tipo pcatp_t*
	descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf); //comenzar captura en modo promiscuo
	if (descr == NULL){
		printf("pcap_open_live(): %s\n",errbuf);
		exit(1);
	}


	//ahora compilo el programa de filtrado para hacer un filtro para ARP o trafico supuestamente enviado por los servers2guard
		//eso de supuestamente enviados se refiere a que me traigo las tramas que tienen ip origen la del los servers ;) asi que de ese modo
			//voy a incluir las spoofeadas y las reales para luego evaluarlas desde el trafficCollector
	//ARMAR FILTRO
	int filterLen=4095;//el tamaño del filtro se calcula segun lo que se tenga para filtrar... pasa que depende de los servers2guard seteados
	filterLen=16*serversQuantity+4;//ip+espacio de cada server mas "arp "
	char filter[filterLen];
	memset(filter,0,filterLen);//inicializo
	//ejemplo: dst host 192.168.1.1 or 192.168.1.100
	strcpy(filter,"host ");
	strcpy(filter+strlen(filter),servers2guardConf[0].ip);//a manopla para plantarle sin el | del lazo for (comodidad ??)

	for(i=1;i<serversQuantity;i++){
		strcpy(filter+strlen(filter)," or ");
		strcpy(filter+strlen(filter),servers2guardConf[i].ip);
	}

	printf("::::el filtro quedo %s \n",filter);

	//COMPILAR FILTRO
	if(pcap_compile(descr,&fp,filter,0,netp)==-1){//luego lo cambiare para filtrar SOLO los mac2guards
		fprintf(stderr,"Error compilando el filtro\n");
		exit(1);
	}
	//Para APLICAR el filtro compilado:
	if(pcap_setfilter(descr,&fp)==-1){
		fprintf(stderr,"Error aplicando el filtro\n");
		exit(1);
	}


	//DETERMINAR EL TAMAÑO DE LA TABLA A PARTIR DE LA MASCARA DE SUBRED
	int arpAskersTable_tableSize=0;

	arpAskersTable_tableSize=networkSize(mask);//Funcion que me devulve cantidad de host segun la mascara de subred

	if(arpAskersTable_tableSize>512){
		printf("ERROR: La red es muy grande...intente con una subred mas chica\n");
                _exit(EXIT_SUCCESS);
        }

	printf("el tamaño de la red es de %d hosts \n",arpAskersTable_tableSize);
	

	--arpAskersTable_tableSize,2;//ajusto el tamaño
	//FIN PARAMETROS DE CAPTURA


	//ajuste por depuracion:
	//arpAskersTable_tableSize=10;//ESTO ES PARA DEBUG NADA MAS


//-----------FINALIZA ZONA DE CONTROL DE PARAMETROS DE APLICACION---------------------------------------------//



//------------INICIA ZONA DE DEFINICION DE ESTRUCTURAS DE DATOS DEL SABUESO--------------
	//vida de los hijos
//	int live=1;//Mas abajo se explica, es para no poner un while true.. ademas me permite INTERRUMPIR la ejecucion

	int subindexCounterId = 0;//es para indizar (o dar ID) a cada entrada de la tabla



	//-------------------------------------------------------------------------------------------------------------------------------------------

	//INICIA CREACION DE TABLA DE SERVERS2GUARD EN MEMORIA COMPARTIDA

	//Crear zona de memoria compartida para alojar la estructura (o.. array de estructuras)

	//puntero a la memoria compartida
	server2guardStruct *servers2guard_shmPtr=NULL;//le tuve que agregar Struct para mantener el array server2guard que tengo con anterioridad


	//descriptor de la memoria compartida
//	int arpAskers_fdshm;
	int servers2guard_fdshm;
	
	//sharedMem
	int servers2guardTable_tableSize=serversQuantity;//calculado dinamicamente con anterioridad ;););)
	//malloqueo para el puntero de la shm
//	arpAskers_shmPtr = (arpAsker *)malloc(sizeof(arpAsker)*arpAskersTable_tableSize);
	servers2guard_shmPtr=(server2guardStruct *)malloc(sizeof(server2guardStruct)*servers2guardTable_tableSize);

	server2guardStruct servers2guardTable[servers2guardTable_tableSize];
	//inicializacion:
	for(subindexCounterId=0;subindexCounterId<servers2guardTable_tableSize;subindexCounterId++){
		memset(servers2guardTable[subindexCounterId].mac,0,40);
		memset(servers2guardTable[subindexCounterId].ip,0,40);
		memset(servers2guardTable[subindexCounterId].serverName,0,30);
		servers2guardTable[subindexCounterId].tos=99;//Type of Service
	}//inicializadas las entradas de la tabla, paso a confeccionar la Memoria Compartida



//---------------------------------------------------------------------------------------------------------------------------------------------------------------------
//VOY A SETEAR LA MEMORIA COMPARTIDA CON LOS MISMO DATOS QUE TENGO EN LA ESTRUCTURA (TEMPORAL, SOLO POR DEBUG, LUEGO SE GUARDARA TODO EN LA SHM DE UNA)
//Esto lo hago asi para apuntar desde el segundo fork directamente con la estructura, mientras que la shm la usan el trafficCollector y otros que precisen acceder
//Como la tabla de servers2guard es SOLO LECTURA, da igual si se leen datos de la shm o de la estructura.. en todo caso es por comodidad y debug...

	for(subindexCounterId=0;subindexCounterId<servers2guardTable_tableSize;subindexCounterId++){
                strcpy(servers2guardTable[subindexCounterId].mac,servers2guardConf[subindexCounterId].mac);
                strcpy(servers2guardTable[subindexCounterId].ip,servers2guardConf[subindexCounterId].ip);
                strcpy(servers2guardTable[subindexCounterId].serverName,servers2guardConf[subindexCounterId].serverName);
                servers2guardTable[subindexCounterId].tos=servers2guardConf[subindexCounterId].tos;//Type of Service
        }
//---------------------------------------------------------------------------------------------------------------------------------------------------------------------


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
	sleep(5);


	//----------------------------------------------------------------------------------------------------------------------------------------------------------


	//INICIA CREACION DE TABLA DE DIALOGOS

	//Crear zona de memoria compartida para alojar la estructura (o.. array de estructuras)

	//puntero a la memoria compartida
	struct arpDialog* shmPtr=NULL;
	//descriptor de la memoria compartida
	int fdshm;
	//sharedMem
//	int subindexCounterId = 0;//es para indizar (o dar ID) a cada entrada de la tabla
//	int tableSize=(arpAskersTable_tableSize*arpAskersTable_tableSize)/2;//maximo de preguntas ARp permitidas por el tamaño de la red
	int tableSize=TABLE_SIZE;
	//malloqueo para el puntero de la shm
	shmPtr = (struct arpDialog *)malloc(sizeof(struct arpDialog)*TABLE_SIZE);
	struct arpDialog arpDialoguesTable[tableSize];//CONSULTAR: AQUI NO DEBERIA MALLOQUEAR?? COREDUMP SI TABLESIZE ES MUY GRANDE!!
	//inicializacion:
	for(subindexCounterId=0;subindexCounterId<tableSize;subindexCounterId++){//ese 100 es el hardcodeado anterior
		arpDialoguesTable[subindexCounterId].arpAskerIndex=subindexCounterId;
		memset(arpDialoguesTable[subindexCounterId].ethSrcMac,0,40);
		memset(arpDialoguesTable[subindexCounterId].ethDstMac,0,40);
		memset(arpDialoguesTable[subindexCounterId].arpSrcMac,0,40);
		memset(arpDialoguesTable[subindexCounterId].arpDstMac,0,40);
		memset(arpDialoguesTable[subindexCounterId].arpSrcIp,0,40);
		memset(arpDialoguesTable[subindexCounterId].arpDstIp,0,40);
		arpDialoguesTable[subindexCounterId].type=99;//0 es pregunta, 1 es respuesta, 99 inicializada
		arpDialoguesTable[subindexCounterId].doCheckIpI=0;
		arpDialoguesTable[subindexCounterId].doCheckSpoofer=0;
		arpDialoguesTable[subindexCounterId].doCheckHosts=0;
		arpDialoguesTable[subindexCounterId].nextState=4;//POR DEFAULT SE MARCA PARA USAR
		arpDialoguesTable[subindexCounterId].askerAssoc=0;//NO ESTA ASOCIADO A NINGUN ASKER (NO SE ALMACENO EL ASKER EN LA TABLA.. TODABIA)
		arpDialoguesTable[subindexCounterId].hit=0;
		//int sem_init(sem_t *sem, int pshared, unsigned int value);
		sem_init(&(arpDialoguesTable[subindexCounterId].semaforo),1,1);//inicializa semaforos de cada entrada de la tabla
	}//inicializadas las entradas de la tabla, paso a confeccionar la Memoria Compartida

	arpDialoguesTable[4].hit=5;
	
	//SHAREDMEM arpDialoguesTableManagerArguments.h
	if(((fdshm=shm_open("/sharedMemDialogos", O_RDWR|O_CREAT, 0666))<0)){
		perror("shm_open()");
		exit(EXIT_FAILURE);
	}
	//lo escribo en blanco
	if(!(write(fdshm,&arpDialoguesTable,sizeof(arpDialoguesTable)))){
	perror("write()");
	exit(EXIT_FAILURE);
	}
	//mapear...
	if(!(shmPtr=mmap(NULL, sizeof(struct arpDialog)*tableSize, PROT_READ|PROT_WRITE, MAP_SHARED, fdshm, 0))){
		perror("mmap()");
		exit(EXIT_FAILURE);
	}
	//la truncada de suerte!!:
	ftruncate(fdshm, sizeof(struct arpDialog)*tableSize);
	close(fdshm);

	//FINALIZA CREACION DE TABLA DE DIALOGOS PARA MEMORIA COMPARTIDA

	//-------------------------------------------------------------------------------------------------------------------------------------------

	//INICIA CREACION DE TABLA DE ASKERS EN MEMORIA COMPARTIDA

	//Crear zona de memoria compartida para alojar la estructura (o.. array de estructuras)

	//puntero a la memoria compartida
	/*struct*/ arpAsker *arpAskers_shmPtr=NULL;

	//descriptor de la memoria compartida
	int arpAskers_fdshm;
	//sharedMem

//RECICLO	int subindexCounterId = 0;//es para indizar (o dar ID) a cada entrada de la tabla 

//	int arpAskersTable_tableSize=10; //lo saco del la netmask cidr obtenida al principio
	
//	arpAskersTable_tableSize=100;//hardcodeado, pero este numero se calcula a partir de la cantidad de IP usables del rango de MI netmask

	//malloqueo para el puntero de la shm
	arpAskers_shmPtr = (arpAsker *)malloc(sizeof(arpAsker)*arpAskersTable_tableSize);

	/*struct*/ arpAsker arpAskersTable[arpAskersTable_tableSize];//CONSULTAR: AQUI NO DEBERIA MALLOQUEAR?? COREDUMP SI TABLESIZE ES MUY GRANDE!!
	//inicializacion:
	for(subindexCounterId=0;subindexCounterId<arpAskersTable_tableSize;subindexCounterId++){//ese 100 es el hardcodeado anterior
		arpAskersTable[subindexCounterId].arpAskerIndex=subindexCounterId;
		memset(arpAskersTable[subindexCounterId].mac,0,40);
		memset(arpAskersTable[subindexCounterId].ip,0,40);
		arpAskersTable[subindexCounterId].status=99;
		arpAskersTable[subindexCounterId].hit=0;
		//int sem_init(sem_t *sem, int pshared, unsigned int value);
		sem_init(&(arpAskersTable[subindexCounterId].semaforo),1,1);//inicializa semaforos de cada entrada de la tabla
	}//inicializadas las entradas de la tabla, paso a confeccionar la Memoria Compartida

//	arpAskersTable[6].hit=9;//ejemplo, vamos a ver si anda la tabla.. =)
	
	//SHAREDMEM arpAskersTable
	if(((arpAskers_fdshm=shm_open("/sharedMemAskers", O_RDWR|O_CREAT, 0666))<0)){//CONSULTAR: que hace aca?!?!?!?
		perror("shm_open()");
		exit(EXIT_FAILURE);
	}
	//lo escribo en blanco
	if(!(write(arpAskers_fdshm,&arpAskersTable,sizeof(arpAskersTable)))){//podria ser el tamaño de una entrada * tarpAskersTable_ableSize como en el mmap??
	perror("write()");
	exit(EXIT_FAILURE);
	}
	//mmapear
	if(!(arpAskers_shmPtr=mmap(NULL, sizeof(arpAsker)*arpAskersTable_tableSize, PROT_READ|PROT_WRITE, MAP_SHARED, arpAskers_fdshm, 0))){
		perror("mmap()");
		exit(EXIT_FAILURE);
	}
	//la truncada de suerte!!:
	ftruncate(arpAskers_fdshm, sizeof(arpAsker)*arpAskersTable_tableSize);
	close(arpAskers_fdshm);

	//FINALIZA LA CREACION DE TABLA DE ASKERS EN MEMORIA COMPARTIDA

//------------FIN ZONA DE DEFINICION DE ESTRUCTURAS DE DATOS DEL SABUESO------------------



//------------INICIA DEFINICION DE ELEMENTOS DE IPC, CONCURRENCIA Y EXCLUSION-------------
	/*
		En este punto definire los PIPES, semaforos, etc...
		nothing to do herer for the moment...
	*/
//------------FIN DEFINICION DE ELEMENTOS DE IPC, CONCURRENCIA Y EXCLUSION----------------




//---------------INICIA FORK PARA RECOLECCION DE TRAFICO (EX ARPCOLLECTOR)----------------------------------------------------------------------------

	//ESTE HIJO ES EL QUE SE ENCARGA DE CAPTURAR TRAMAS, EVALUARLAS, ALMACENARLAS Y ADMINISTRAR ASKERS.
	//EN CASO DE DETECTARSE UNA CASO DE SPOOFING, SE ENVIARA UNA SALIDA AL SYSLOG DEL SISTEMA O PODRA AÑADIRSE FUNCIONES DE ALERTA


	switch(fork()){
		case -1:
			perror("fork()");
			_exit(EXIT_FAILURE);
		case 0:
			//Proceso trafficCollector.c
			puts("\n----------------------------");
			puts("INICIANDO TRAFFIC COLLECTOR...\n");

			//Argumentos para la funcion callback
			trafficCCArgs conf[2] = {
				{tableSize, "Argumentos",shmPtr,arpAskers_shmPtr,arpAskersTable_tableSize,servers2guard_shmPtr,servers2guardTable_tableSize}
			};
			//El bucle de captura lo armo con variables que el padre ya preparo antes cuando hizo el check de la netmask
			pcap_loop(descr,-1,(pcap_handler)trafficCollector_callback,(u_char*) conf);
			_exit(EXIT_SUCCESS);
	}//FIN DEL FORK PARA TRAFFIC ARPCOLLECTOR


//---------------FIN FORK PARA RECOLECCION DE TRAFICO (EX ARPCOLLECTOR)---------------------------------------------------------------------------------


	//Continua el padre...
	//ahora recorrer el array de servers que tengo que "cuidar" (monitorear) Y LANZAR UN HIJO PARA CADA SERVER2GUARD
	//Recordemos que cada host que tenga interes en hablar con estos servers (que tienen informacion sensible) son
	//posibles victimas de ataques arp spoofing.

	//LUEGO DESDE ESTOS HIJOS, PORTSTELEAR A LAS POSIBLES VICTIMAS (CLIENTES DEL SERVER2GUARD) Y ENCONMENDARSE AL TRAFFCICOLLECTOR PARA EL ANALISIS DE LAS TRAMAS ROBADAS





	//Ahora por cada uno de los hosts a monitorear lanzar un HIJO

	for(i=0;i<serversQuantity;i++){
		//------------INICIA FORK MULTIHILADO DE SEGUIMIENTO, ROBO DE PUERTO Y ALERTA-----------------------------
		switch(fork()){
			case -1:
				perror("fork()");
				_exit(EXIT_FAILURE);
			case 0:
				sleep(5);
				printf("INICIANDO HIJO PORT STEALER PARA EL SERVER2GUARD: %s\n",(servers2guardConf[i].serverName));
//----------------------------------------
				while(1==1){
					sleep(1);
					
					printf("mostrando memoria compartida desde el port stealer pasada %d\n",j);
					for(c=0;c<tableSize;c++){
						printf("entrada %d  |%s  ",c,shmPtr[c].ethSrcMac);
						printf("|%s  ",shmPtr[c].ethDstMac);
						printf("|%s  ",shmPtr[c].arpSrcMac);
						printf("|%s  ",shmPtr[c].arpDstMac);
						printf("|%s  ",shmPtr[c].arpSrcIp);
						printf("|%s \n",shmPtr[c].arpDstIp);
					}
					j++;
					break;//No me iba a quedar en el while true ni loco!!! AJJajJJAAJJAaaaaa
				}
//------------------------------------------

				//ALGORITMO:
				//1|Examinar entrada por entrada de la tabla de dialogos y para cada una analizar si su destino es ESTE server2guard
				//tableSize, shmPtr[j], servers2guardConf[i] (lo mismo que la shm de s2g),arpAskersTable_tableSize, arpAskers_shmPtr[a],dev, pstlRepeatLimit,pstlPoolingTime,pstlSleepTime

				
				pstFunction(tableSize, shmPtr, servers2guardConf,arpAskersTable_tableSize, arpAskers_shmPtr,dev, pstlRepeatLimit,pstlPoolingTime,pstlSleepTime);

/*
				return;

				live=1;
				int forlife=0;
				while(live==1){//podria ser un while true, se utilizo esta variable para tener condicion de corte (aunque puedo usar break...)

					sleep(5);//descanza 5 segundos antes de cada NUEVA recorrida completa

					for(j=0;j<tableSize;j++){
						printf("Comenzando el lazo por %d° vez\n",j);

						//Mostrar datos de la entrada ACUTAL segun j:

						printf("el nextState = %d\n",shmPtr[j].nextState);
						printf("el type = %d\n",shmPtr[j].type);
						printf("src: %s dst: %s\n",shmPtr[j].arpSrcIp,shmPtr[j].arpDstIp);

						//SOLO ME IMPORTAN LAS ENTRADAS CON nextState==1 PORQUE SON LAS QUE AÑADIO EL TRAFFIC COLLECTOR
						//ADEMAS, SI LA AÑADIO.. SEGURO NO ES NULL Y PUEDO ANALIZARLA TRANQUILO

						//ENTONCES SI LA TRAMA ESTA MARCADA DIFERENTE A 1 ENTONCES LA PASO POR ALTO Y VUELVE AL PRINCIPIO DEL FOR PARA ANALIZAR LA PROXIMA ENTRADA SEGUN J(J++)
						if(shmPtr[j].nextState!=1){
							printf("La entrada NO estaba marcada para checkear (%d) salto a la proxima\n",shmPtr[j].nextState);
							continue;//salto a la proxima entrada de la tabla
						}

						//SI CONTINUA ACA, SIGNIFICA QUE LA ENTRADA ESTABA MARCADA CON SU NEXTSTATE EN 1 =)

						//IGUAL ANALIZO SI NO ES RECIEN INICIALIZADA...(por comprobar no mas)
						if(shmPtr[j].type==99){//recien inicializada (ES NULL...)
							printf("<<Entrada vacia, continuar con la siguiente\n");
							continue;//salta a la proxima entrada de la tabla
						}
						else{//si no esta "vacia" (inicializada en realiadad.."
							printf("<<Esta entrada no esta vacia!!! ahora va al if de si coincide con el server que cuido...\n");
							printf("<<comparando i: %s con shmPtr: %s \n",servers2guardConf[i].ip,shmPtr[j].arpDstIp);
						}


						//SI CONTINUA ACA, SIGNIFICA QUE SE PUEDE ANALIZAR...(NO ES UNA ENTRADA RECIEN INICIALIZADA)

						//controlo el largo del srcIP como segunda medida de consistencia de la entrada (nextState no es confiable...?)
						if(7>(int)strlen(shmPtr[j].arpSrcIp)){
							printf("EPAA el largo de la srcip leido desde la tabla es menor que 7!!(no deberia mostrarse nunca\n");
							continue;//interrumpe el ciclo actual...
						}

						//SI CONTINUA ACA, SIGNIFICA QUE ESTA TODO OK EN LA ENTRADA DE LA TABLA...ES ANALIZABLE

						//AHORA ANALIZO SI ESTE SERVER2GUARD ES DESTINO DE ESTA ENTRADA DE TABLA, PARA SABER SI LA ANALIZO O NO

						printf("comparando server2guard ip: %s con shmPtr dest ip: %s \n",servers2guardConf[i].ip,shmPtr[j].arpDstIp);

						//PARA ESTA COMPARACION, PRIMERO COMPARO EL LARGO DE AMBAS, SI ES IGUAL AHI RECIEN COMPARO BYE A BYTE

						if(strlen(servers2guardConf[i].ip)!=strlen(shmPtr[j].arpDstIp)){
							printf(">> PST: NO tienen el mismo largo!! continue a la siguiente entrada...\n");
							continue;//YA SE QUE ESTE SERVER2GUARD NO ES DESTINO EN ESTA ENTRADA DE TABLA, SALTAR A LA PROXIMA ENTRADA DE TABLA, REINICIAR FOR CON J++
						}
		
						//EN CAMBIO SI SIGUE ACA, SIGNIFICA QUE TUVIERON EL MISMO LARGO, ASI QUE LAS COMPARO BYTE A BYTE
						printf(">> PST: SI tienen el mismo largo,es posible que esta entrada sea destinada a este server2guard\n");
						
						//COMPARAR BYE A BYTE CON STRNCMP
						if(!strncmp(servers2guardConf[i].ip,shmPtr[j].arpDstIp,strlen(shmPtr[j].arpDstIp))){
							printf(">>>PST:(eran iguales) Entrada destinada al server %s\n",(servers2guardConf[i].serverName));
							//evaluo si la entrada es pregunta o respuesta arp (solo salvo arp, y de momento solo me importan PREGUNAS porque develan intencion de dialogo)
							//La intencion de dialogo quiere decir que el que pregunta (asker) quiere comunicarse con un server (y consumir sus servicios muy probable es)

							switch(shmPtr[j].type){
								case 0:
									printf(">>ES UNA PREGUNTA ARP (INTENCION DE DIALOGO EXPRESADA)...\n");
								break;
								case 1:
									printf(">>ES UNA RESPUESTA ARP (SALTAR por ahora)\n");//NO ES PARTE DEL ALCANCE ACTUAL
									//de momento continua a la siguiente
									continue;//Esto obliga a que se continue SOLO si son preguntas ARP (obviando responses)
								break;
								default:
									printf(">>PST: ERROR: ANOMALIA EN LA ENTRADA DE LA TABLA ANALIZADA\n");
									continue;
								break;
							}//switch tipo de trama en la j entrada de la tabla

						}//IF la entrada es realmente para este server
						else{
							printf(">>>PST: Esta entrada NO es para este server, salte a la siguiente\n");
							continue;//Para que siga con la proxima entrada en la tabla
						}
						//SI no entro al else.. continua la ejecucion dado que la entrada era para el server


						int askerToLockFounded=0;//flag para saber si se podra bloquear el asker...sino lo encuentor no puedo!
						int a=0;//subindice de recorrido de askers

						//-----------------------------------------------------------------------------------------------------------------------
						//SI HIT > 1, ENTONCES SALTO (este control no ha ofrecido mucho perfomance, quiza lo elimine en proximas versiones)
						//La idea es no portstelear seguido al mismo cliente por eso el HIT...peeero no ha sido muuuy representativa la mejora

						if(shmPtr[j].hit > 2){
							printf("el HIT (%d) era mayor que 2 en el portstealer, saltando a la proxima trama..\n",shmPtr[j].hit);
							continue;//salto.. hasta que la vea el traffic de nuevo...
						}
						else{
							printf("el HIT (%d) no era mayor que 2 asi que procedo a portstelear...\n",shmPtr[j].hit);
						}
						//------------------------------------------------------------------------------------------------------------------------
							

						printf("PST: ahora busco el ASKER en la tabla para proceder...\n");

						//------------------------------------------------------------------------------------------------------------------------

						//ANTES DE BUSCAR EL ASKER.. ME FIJO QUE LA ENTRADA DE LA TABLA TENGA ASOCIACION DE ASKER
						//(tampoco ha dado mucho resultado, y basicamente era para demorar mientras el trafficCollector guardaba el asker.. pero no es necesario esto)

						printf("comprobando asociacion con asker...\n");
						for(a=0;a<10;a++){
							if(shmPtr[j].askerAssoc!=1){
								printf("NO ESTA ASOCIADA A NINGUN ASKER ESTA ENTRADA!!!\n");
								sleep(1);
							}
							else{
								printf("segun el atributo askerAssoc esta entrada cuenta con asociacion a asker\n");
								break;
							}
						}
						printf("segun las comprobaciones, esta entrada de tabla tiene askerAssoc=%d\n",shmPtr[j].askerAssoc);

						//------------------------------------------------------------------------------------------------------------------------

						//AQUI COMIENZA A RECORRER LA TABLA DE ASKERS, PARA ENCONTRAR AL SENDER DE ESTA TRAMA Y LOCKEARLO (PARA QUE NADIE MAS LO PORTSTELEE AL MISMO TIEMPO)
						//La idea de meter hilos tambien lo bueno que tiene es que cuando otro HIJO de server2gurd se bloquea esperando que se libere al asker
						//podria paraleleamente ir portsteleando otros clientes y no congelarse en esa espera como lo hace actualmente.
						//El diseño lo soporta, pero el alcance de la implementacion se ha acotado para limitar la app solo a la PoC del trabajo final.

						//RECORRER TABLA DE ASKERS

						for(a=0;a<arpAskersTable_tableSize;a++){


							//si el largo coincide comparo:
							printf("entrada askers %d\n",a);
							printf("<comparar largo de askerEntry=%s y tableEntry=%s\n",arpAskers_shmPtr[a].ip,shmPtr[j].arpSrcIp);

							//primero comparo el largo, saltando a la proxima si son distintas.

							if(strlen(arpAskers_shmPtr[a].ip)!=strlen(shmPtr[j].arpSrcIp)){
								printf("<comparacion de largo de asker antes de bloquear fallo...\n");
								continue;//continue con el siguiente asker...
							}
							//Si tuvo el mismo largo, comparar byte a byte:
							printf("mismo largo.. ahora comparar caracter a caracter...\n");
							if(!strncmp(arpAskers_shmPtr[a].ip,shmPtr[j].arpSrcIp,strlen(shmPtr[j].arpSrcIp))){
								printf("<comparacion dio igual =)\n");
								askerToLockFounded=1;//flag arriba! puedo lockearlo porque lo encontre en "a"
								//lo bloqueo y me aseguro de que sigue alli:
								sem_wait((sem_t*) & arpAskers_shmPtr[a].semaforo);
								//lo vuelvo a COMPARAR (por si justo el traffic lo modifico)
								askerToLockFounded=0;
								//RECOMPARAR:
								if(strlen(arpAskers_shmPtr[a].ip)!=strlen(shmPtr[j].arpSrcIp)){
									printf("<segunda comparacion de largo de asker antes de bloquear fallo...\n");
									//unlockeo
									sem_post((sem_t*) & arpAskers_shmPtr[a].semaforo);
									askerToLockFounded=0;//no lo encontro al final
									break;//finaliza el for sin conseguir al asker...
								}
								printf("Segunda comparacion de largo de asker coincidio nuevamente...\n");
								//comparo por strncmp
								if(!strncmp(arpAskers_shmPtr[a].ip,shmPtr[j].arpSrcIp,strlen(shmPtr[j].arpSrcIp))){
									printf("<segundo strncmp del asker coincide =)\n");
									askerToLockFounded=1;//lo usa un if luego para ejecutar el algoritmo =)
									arpAskers_shmPtr[a].status=2;//lo pongo en checking...
									break;//no sigo buscado.. me voy derecho al algoritmo =)
								}
								else{
									printf("<no coincidio en la segunda comparacion del asker.libero y cancelo\n");
									sem_post((sem_t*) & arpAskers_shmPtr[a].semaforo);
									askerToLockFounded=0;
									break;//no sigo buscando.. ya fue..
								}
							}//if del primer strncmp de asker
							else{//mismo largo, distinto asker...
								printf("<mismo largo pero el asker no era este\n");
								continue;//siga con el proximo asker
							}
						}//lazo for que busca lockear al asker...(para que nadie mas le robe el puerto!!)
						//ANALIZAR COMO HA IDO LA BUSQUEDA Y LOCK DEL ASKER:

						printf("bueno ahora me fijo si fue un fracaso la busqueda del asker o si continua...\n");

						if(askerToLockFounded==0){//evaluar si sigo con el algoritmo o salto al proximo pregunton...
							printf("<Fracaso el intento de encontrar el asker para lockearlo y portstelear,saltar!\n");
							continue;//salta al proximo
						}
						else{
							//SI entra aqui significa que lo encontro al asker, asi que puedo continuar con el portstealing =)
							printf("continuar con el algoritmo de portstealing por encontrar al asker en a=%d\n",a);
							//no hace continue.. porque sigue con ESTE mismo
						}


						//CONTINUAR CON EL ALGORITMO (implementacion de PoC de la Tesis)

						//Explicacion del loop:
						//Si bien es lo mas parecido a un while true, no es infinito.. de hecho hay un limite de veces que se repite el algoritmo
						//ESE LIMITE esta determinado por el parametro pstlRepeatLimit que indica cuantas veces como MUCHO se va a repetir el loop del while 1 == 1

						printf("<<>> Comienza el loop para portstealing...\n");
						//LOOP:
						int pst=0;//Para el algoritmo de portstealing (contador)
						int times=0;//PARA SABER CUANTAS VECES EJECUTE EL ALGORITMO Y CORTAR PARA EVITAR INANICION
						while(1==1){
							printf("Valor de times en esta vuelta: times=%d\n",times);

							printf("<<>>Dentro del while del status, comenzando el portstealing\n");
							
							//portstealing (rafaga de robo de puerto) -> Sacada del script de pruebas tester.sh
							printf("PST-MAIN: RAFAGA...\n");
							for(pst=0;pst<20;pst++){
								arper(shmPtr[j].ethSrcMac,shmPtr[j].arpSrcIp,shmPtr[j].arpDstIp,dev);
								usleep(100);
							}
//							printf("PST-MAIN: PORTSTEALING 7 SEGUNDOS....\n");
							printf("PST-MAIN: PORTSTEALING %d SEGUNDOS....\n",pstlPoolingTime);

							//portstealing (robo de tramas)
							for(pst=0;pst<pstlPoolingTime;pst++){//7 o el pstlPoolingTime es la cantidad de mensajes, pero como sin cada 1 seg .. resulta en tiempo igual :/
								arper(shmPtr[j].ethSrcMac,shmPtr[j].arpSrcIp,shmPtr[j].arpDstIp,dev);//LLAMADA OK
								printf("PST-MAIN: PORTSTEALING MESSSAGE %d\n",pst);
								usleep(1000000);
							}
							printf("PST-MAIN: DEVOLVIENDO EL PUERTO AL CLIENTE...\n");
							//Arpear por el asker (para que recupere el puerto)
							for(pst=0;pst<10;pst++){
                                                                arper("default","default",shmPtr[j].arpSrcIp,dev);//LLAMADA OK
                                                                usleep(100000);
                                                        }
							printf("PST-MAIN: Algortimo completado!!!\n");

							//EVALUAR SI FUE SUFICIENTE O SI DUERMO Y SIGO...
							if(times==pstlRepeatLimit){//aqui es donde entra en juego el pstlRepeatLimit
								printf("Ya ha sido demaciado, asi que salto al proximo asker a portstelear...\n");
								break;
							}
							times++;
							//SI NO HA SIDO SUFICIENTE, CONTINUA...
							//PERO VA A DEMORAR EL SIGUIENTE CICLO, PARA NO AFECTAR PERFOMANCE DE LA RED, PARA ELLO UTILIZA pstlSleepTime

							printf("PST-MAIN: dormir antes de bombardear nuevamente...\n");

							sleep(pstlSleepTime);//este es el pstlSleepTime (10 para las prubeas en debug)

							printf("PST-MAIN: despertar al algoritmo =) \n");
						}//end while status == checking


						printf("PST-MAIN: atencion: saliendo del loop de portstealing. Se ha informado la deteccion de un SPOOFER\n");
						//END LOOP

						//--------------------------------------------------------------------------------------------------------------
						//INCREMENTAR EL HIT
						printf("valor del HIT antes: %d\n",shmPtr[j].hit);
						shmPtr[j].hit=shmPtr[j].hit + 1;//incremento el hit para no reespoofearla al vicio
						printf("incrementado el HIT para no volver a spoofear al vicio...\n");
						printf("valor del HIT luego: %d\n",shmPtr[j].hit);
						//--------------------------------------------------------------------------------------------------------------

						//FORZAR EL STATUS A CHECK PARA QUE SI OTRO PROCESO ESTABA ESPERANDO EL UNLOCK, PUEDA PROCEDER AL CHECKEAR
						arpAskers_shmPtr[a].status=2;
						//AL FINAL:::liberar:
						sem_post((sem_t*) & arpAskers_shmPtr[a].semaforo);
						printf("<liberado el semaforo del asker portsteleado\n");


						//UNA VEZ COMPROBADO ESTE ASKER, DEBERIA LIMPIAR DE LA TABLA TODOS LOS CASOS PARA ESTE ASKER
							//DE ESTE MODO LA TABLA NO SE LLENA SIEMPRE DE LO MISMO
							//TAMPOCO SUCEDE QUE SE REPITE EL PORTSTEALING EN VANO (MISMO SERVER Y MISMO CLIENTE)

						//	Y ESTE SERVER ;) (PARA OTROS SERVERS SE ENCARGAN OTROS HIJOS DEL LOOP)

						//LAZO FOR QUE RECORRE BUSCANDO COINCIDENCIAS Y ELIMINA LAS QUE SON ORIGEN EL ASKER DESTINO EL SERVER
						// LAS QUE SON INVERSAS TAMBIEN DEBERIA PORQUE NO LAS ESTOY TRATANDO DE MOMENTO.


						printf("finalizado el algoritmo, prosigo con la siguiente entrada de la tabla tabla, la vida de este for=%d\n",forlife);
						forlife++;
						
					}//CIERRO EL FOR QUE RECORRE LA TABLA PRINCIPAL DE DIALOGOS, AQUI SIGUE DENTRO DEL LOOP WHILE(LIVE==1)
					//CONTINUANDO EN EL WHILE LIVE==1...

					printf("Descanzare 5 segs y de nuevo lanzo el for...\n");
				}//CIERRO EL WHILE LIVE ==1


				*/


				_exit(EXIT_SUCCESS);//del hijo de este ciclo del for

		}//CIERRO EL SWITCH FORK (tiene doble identacion del switch case fork
	}//LAZO FOR PARA LANZAR HIJOS PARA CADA SERVER QUE TENGO QUE MONITOREAR



		//------------FIN FOR DE FORKS SEGUIMIENTO, ROBO DE PUERTO Y ALERTA--------------------------------



	//UNA VEZ LANZADOS LOS HIJOS PARA CADA SERVER, CONTINUA EL PADRE...

	//FIN LABOR PADRE (si.. en general digamos)

	//fin del programa principal
	//el siguiente sleep va a cambiar por un lazo que corre durante la vida del programa... alli ya no va a haber problema de que temrine el padre..

	while(1==1){
		sleep(1);//el padre no muere.. sino me quedan los hijos ahi colgados!!
	}

	write(1,"FIN DEL PROGRAMA PRINCIPAL\n",sizeof("FIN DEL PROGRAMA PRINCIPAL\n"));
	return EXIT_FAILURE;//_exit(EXIT_SUCCESS);
}//fin del programa
