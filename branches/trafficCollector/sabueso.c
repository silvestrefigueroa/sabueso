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
//#include "parser.h"
//#include "splitter.h" //LO SAQUE POR DESUSO Y PARA LIMPIAR UN POCO DE CODIGO
#include "arpDialogStruct.h"
//#include "arpAskerStruct.h"
#include "trafficCollector_callback.h"
#include "callbackArgs.h"

//#include "arpDialoguesTableManager.h"//se removio de este branche.. tarde pero se removio
//#include "arpDialoguesTableManagerArguments.h" //y si.. tambien se removio este por supuesto
//#include "arpDTMWorker_arguments_struct.h"

//MENSAJES ESTATICOS
#define MSG_START "Comienza aqui el programa principal\n"

//MACROS DE ARGS
#define TABLE_SIZE 4

//Icludes del trafficCollector.c
//#include <unistd.h>
//#include <stdio.h>
//#include <stdlib.h>
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

//Aqui comienza la magia =)
int main(int argc, char *argv[]){
	/*
	char *cadenilla="sysloguenadooooooooooooooooooooooooooo";
	syslog(1, "%s", cadenilla);
	printf("syslogueado\n");
	return 0;
	*/


	//manejador SIGTERM
	signal(SIGINT , sigint_handler);

	if(0>=write(1,MSG_START, strlen(MSG_START)))
		return -1;
	int i=0;//indice utilizando en los for...
//------------INICIA ZONA DE CONTROL DE PARAMETROS DE APLICACION-----------------------------------------------//
	//PARAMETROS DE LANZAMIENTO:

	//----VOY A HARDCODEAR LOS PARAMETROS DE MOMENTO:

	int serversQuantity=5;//cantidad de servers a cuidar

	//Estructura de datos de argumentos del programa principal
	typedef struct{ 
                char *mac;
                char *ip;
		char *serverName;
                int tos;//0 http,1 rdp
        }_server2guard;

	_server2guard _servers2guard[serversQuantity];//array de servers

	//inicializar array de struct:
	for(i=0;i<serversQuantity;i++){
		_servers2guard[i].mac=NULL;
		_servers2guard[i].ip=NULL;
		_servers2guard[i].tos=0;
		_servers2guard[i].serverName=NULL;
	}
	//invento hosts

	_servers2guard[2].mac="e0:db:55:88:66:71";
	_servers2guard[2].ip="192.168.222.2";
	_servers2guard[2].tos=0;
	_servers2guard[2].serverName="server-windows7";
	

	_servers2guard[3].mac="12:43:56:a:a:2";//hacker ubuntu por las dudas es: 00:50:56:2f:9e:e5
	_servers2guard[3].ip="192.168.1.126";
	_servers2guard[3].tos=0;
	_servers2guard[3].serverName="server-126";

	_servers2guard[4].mac="0:50:56:38:7c:ae";
	_servers2guard[4].ip="192.168.222.44";
	_servers2guard[4].tos=0;
	_servers2guard[4].serverName="cliente-ubuntu";

	_servers2guard[0].mac="5c:d9:98:2c:f:b6";//seria 5c:d9:98:2c:0f:b6
	_servers2guard[0].ip="192.168.1.1";
	_servers2guard[0].tos=0;
	_servers2guard[0].serverName="dd-wrt";

	_servers2guard[1].mac="0:21:5c:33:9:a5";//para pcap seria 0:21:5c:33:9:a5 mientras que la real seria "00:21:5c:33:09:a5"
	_servers2guard[1].ip="192.168.1.100";
	_servers2guard[1].tos=0;
	_servers2guard[1].serverName="Thinkpad-100-myself";


	int j=0;//otro subindice

	int c=0;
	int live=0;
	serversQuantity=1;



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
	dev = pcap_lookupdev(errbuf); //Buscamos un dispositivo del que comenzar la captura
	printf("\nEcontro como dispositivo %s\n",dev);
	if (dev == NULL){
		fprintf(stderr," %s\n",errbuf); exit(1);
	}
	else{
		printf("Abriendo %s en modo promiscuo\n",dev);
	}
	dev = "wlan0";//hardcodeo la wifi en desarrollo, luego la dejare utomatica o por parametro.
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
	strcpy(filter+strlen(filter),_servers2guard[0].ip);//a manopla para plantarle sin el | del lazo for (comodidad ??)

	for(i=1;i<serversQuantity;i++){
		strcpy(filter+strlen(filter)," or ");
		strcpy(filter+strlen(filter),_servers2guard[i].ip);
	}

	printf("::::el filtro quedo %s \n",filter);
//	return 0;

	//COMPILAR FILTRO
	if(pcap_compile(descr,&fp,"arp"/*filter*/,0,netp)==-1){//luego lo cambiare para filtrar SOLO los mac2guards
		fprintf(stderr,"Error compilando el filtro\n");
		exit(1);
	}
	//Para APLICAR el filtro compilado:
	if(pcap_setfilter(descr,&fp)==-1){
		fprintf(stderr,"Error aplicando el filtro\n");
		exit(1);
	}
	//calculo el tamaño de la table para askers en funcion de la mascara de subred:
	int maskTooBig=1;
	int arpAskersTable_tableSize=0;
	for(i=0;i<1;i++){
		if(!strncmp(mask,"255.255.255.254",strlen("255.255.255.254"))){
			printf("en cidr es una /31\n");
			maskTooBig=0;
			arpAskersTable_tableSize=2;
			break;//rompe el bucle
		}
		if(!strncmp(mask,"255.255.255.252",strlen("255.255.255.252"))){
			printf("en cidr es una /30\n");
			maskTooBig=0;
			arpAskersTable_tableSize=4;
			break;//rompe el bucle
		}
		if(!strncmp(mask,"255.255.255.248",strlen("255.255.255.248"))){
			printf("en cidr es una /29\n");
			arpAskersTable_tableSize=8;
			maskTooBig=0;
			break;//rompe el bucle
		}
		if(!strncmp(mask,"255.255.255.240",strlen("255.255.255.240"))){
			printf("en cidr es una /28\n");
			arpAskersTable_tableSize=16;
			maskTooBig=0;
			break;//rompe el bucle
		}
		if(!strncmp(mask,"255.255.255.224",strlen("255.255.255.224"))){
			printf("en cidr es una /27\n");
			arpAskersTable_tableSize=32;
			maskTooBig=0;
			break;//rompe el bucle
		}
		if(!strncmp(mask,"255.255.255.192",strlen("255.255.255.192"))){
			printf("en cidr es una /26\n");
			arpAskersTable_tableSize=64;
			maskTooBig=0;
			break;//rompe el bucle
		}
		if(!strncmp(mask,"255.255.255.128",strlen("255.255.255.128"))){
			printf("en cidr es una /25\n");
			arpAskersTable_tableSize=128;
			maskTooBig=0;
			break;//rompe el bucle
		}
		if(!strncmp(mask,"255.255.255.0",strlen("255.255.255.0"))){
			printf("en cidr es una /24\n");
			arpAskersTable_tableSize=256;
			maskTooBig=0;
			break;//rompe el bucle
		}
		if(!strncmp(mask,"255.255.254.0",strlen("255.255.254.0"))){
			printf("en cidr es una /23\n");
			arpAskersTable_tableSize=512;
			maskTooBig=0;
			break;//rompe el bucle
		}
	}
	if(maskTooBig==1){
		printf("ERROR: La red es muy grande...intente con una subred mas chica\n");
		_exit(EXIT_SUCCESS);
	}
	--arpAskersTable_tableSize,2;//ajusto el tamaño
	//FIN PARAMETROS DE CAPTURA


	//ajuste por depuracion:
	arpAskersTable_tableSize=10;


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

//VOY A SETEAR LA MEMORIA COMPARTIDA CON LOS MISMO DATOS QUE TENGO EN LA ESTRUCTURA (TEMPORAL, SOLO POR DEBUG, LUEGO SE GUARDARA TODO EN LA SHM DE UNA)

	for(subindexCounterId=0;subindexCounterId<servers2guardTable_tableSize;subindexCounterId++){
                strcpy(servers2guardTable[subindexCounterId].mac,_servers2guard[subindexCounterId].mac);
                strcpy(servers2guardTable[subindexCounterId].ip,_servers2guard[subindexCounterId].ip);
                strcpy(servers2guardTable[subindexCounterId].serverName,_servers2guard[subindexCounterId].serverName);
                servers2guardTable[subindexCounterId].tos=_servers2guard[subindexCounterId].tos;//Type of Service
        }





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
	//ojo con ese 100 de abajo.. es el hardcodeado, representa la cantidad de estructuras struct arpDilog que hay en el array arpDialoguesTable
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
	
	arpAskersTable_tableSize=100;//hardcodeado, pero este numero se calcula a partir de la cantidad de IP usables del rango de MI netmask
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

	arpAskersTable[6].hit=9;//ejemplo, vamos a ver si anda la tabla.. =)
	
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
	//ojo con ese 100 de abajo.. es el hardcodeado, representa la cantidad de estructuras struct arpDilog que hay en el array arpDialoguesTable
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
	*/
//------------FIN DEFINICION DE ELEMENTOS DE IPC, CONCURRENCIA Y EXCLUSION----------------


//---------------INICIA FORK PARA RECOLECCION DE ARP EN EL BROADCAST O MODULO ARPCOLLECTOR-----------------------------
	switch(fork()){
		case -1:
			perror("fork()");
			_exit(EXIT_FAILURE);
		case 0:
			//Proceso trafficCollector.c
			puts("\n-------------------------");
			puts("soy el HIJO recolector de mensajes ARP iniciando...\n");
	
			//COmienza a preparar la captura...
			dev=NULL;
			net=NULL;
			mask=NULL;
			//Argumentos para la funcion callback
			trafficCCArgs conf[2] = {
				{tableSize, "Argumentos",shmPtr,arpAskers_shmPtr,arpAskersTable_tableSize,servers2guard_shmPtr,servers2guardTable_tableSize}
//				{tableSize, "Argumentos",shmPtr,arpAskers_shmPtr,arpAskersTable_tableSize}

			};
			//El bucle de captura lo armo con variables que el padre ya preparo antes cuando hizo el check de la netmask
			pcap_loop(descr,-1,(pcap_handler)trafficCollector_callback,(u_char*) conf);
			_exit(EXIT_SUCCESS);
	}//FIN DEL FORK PARA ARPCOLLECTOR


//---------------FIN FORK PARA RECOLECCION DE ARP EN EL BROADCAST O MODULO ARPCOLLECTOR-----------------------------

	//Continua el padre...
	//ahora recorrer el array de servers que tengo que "cuidar" (monitorear)
	//Recordemos que cada host que tenga interes en hablar con estos servers (que tienen informacion sensible) son
	//posibles victimas de ataques arp spoofing.
	//Ahora lo que voy a hacer, es por cada uno de los hosts a monitorear lanzar un HIJO con la funcion correspondiente.
/*
	while(1==1){
		sleep(1);
		
		printf("mostrando memoria compartida desde el port stealer pasada %d\n",j);
		for(c=0;c<tableSize;c++){
			printf("entrada %d  |%s  ",c,shmPtr[c].ethSrcMac);
			printf("|%s  ",shmPtr[c].ethDstMac);
			printf("|%s  ",shmPtr[c].arpSrcMac);
			printf("|%s  ",shmPtr[c].arpSrcMac);
			printf("|%s  ",shmPtr[c].arpSrcIp);
			printf("|%s \n",shmPtr[c].arpDstIp);
		}
		j++;
	}
*/


	for(i=0;i<serversQuantity;i++){
		//------------INICIA FORK MULTIHILADO DE SEGUIMIENTO, ROBO DE PUERTO Y ALERTA-----------------------------
		switch(fork()){
			case -1:
				perror("fork()");
				_exit(EXIT_FAILURE);
			case 0:
				sleep(5);
				printf("soy el HIJO PORT STEALER del server: %s\n",(_servers2guard[i].serverName));
				j=0;
				c=0;
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
					break;
				}
//------------------------------------------

				printf("continuando con el portstealer\n");
				//flags:
				int askingForThisServer=0;//inicializa en "no preguntan por el server"
				int responseForThisServer=0;//cuando es este server el que respondio
							
				//ALGORITMO:
				//1|Examinar entrada por entrada de la tabla y para cada una:
				live=1;
				j=0;
				int forlife=0;
				while(live==1){//podria ser un while true, se utilizo esta variable para tener condicion de corte (aunque puedo usar break...)
					sleep(5);//descanza 5 segundos antes de cada recorrida completa
					printf("<<<< vuelta aquiiiii\n");
					for(j=0;j<tableSize;j++){
						printf("dentro del for con j=%d\n",j);
						//por las dudas me fijo si la entrada en la tabla no es NULL:
						printf("el nextState = %d\n",shmPtr[j].nextState);
						printf("el type = %d\n",shmPtr[j].type);
						printf("src: %s dst: %s\n",shmPtr[j].arpSrcIp,shmPtr[j].arpDstIp);
						//SI LA TRAMA ESTA MARCADA DIFERENTE A 1 ENTONCES LA PASO POR ALTO
						if(shmPtr[j].nextState!=1){
							printf("La entrada NO estaba marcada para checkear (%d) salto a la proxima\n",shmPtr[j].nextState);
							continue;//salto a la proxima entrada de la tabla
						}
						//else... continua la ejecucion de codigo normalmente..

//						if(shmPtr[j].nextState==99){//si es una entrada recien inicializada que lo salte
						if(shmPtr[j].type==99){//recien inicializada (ES NULL...)
							printf("<<Entrada vacia, continuar con la siguiente\n");
							continue;//salta a la proxima entrada de la tabla
						}
						else{//si no esta "vacia" (inicializada en realiadad.."
							printf("<<Esta entrada no esta vacia!!! ahora va al if de si coincide con el server que cuido...\n");
							printf("<<comparando i: %s con shmPtr: %s \n",_servers2guard[i].ip,shmPtr[j].arpDstIp);
						}
						//continua aca porque no cayo en el if de si estaba inicializada

						//controlo el largo del srcIP a ver si realmente no estaba vacia la entrada (nextState no es confiable...?)
						if(7>(int)strlen(shmPtr[j].arpSrcIp)){
							printf("EPAA el largo de la srcip leido desde la tabla es menor que 7!!(no deberia mostrarse nunca\n");
							continue;//interrumpe el ciclo actual...
						}
						//else...seguir aqui =)
						//1.99 Si esta involucrado ESTE server:

						//si es destino
						printf("comparando i: %s con shmPtr: %s \n",_servers2guard[i].ip,shmPtr[j].arpDstIp);
						//PARCHE por largo..(antes de strncmp me fijo si tienen el mismo largo.. sino son distintas de una..
						if(strlen(_servers2guard[i].ip)!=strlen(shmPtr[j].arpDstIp)){//distinta logica, mismo metodo (strlen)
							printf(">> PST: NO tienen el mismo largo!! continue a la siguiente entrada...\n");
							continue;//que no siga la ejecucion con esta entrada y pase derecho a la proxima
						}
						//Si sigo aca es porque tenian el mismo largo
						printf(">> PST: SI tienen el mismo largo, ahora evaluo si son iguales (es decir, si es de este server)\n");
						
						if(!strncmp(_servers2guard[i].ip,shmPtr[j].arpDstIp,strlen(shmPtr[j].arpDstIp))){//ip es del server i
							printf(">>>PST: (eran iguales) Entrada esta destinada al server %s\n",(_servers2guard[i].serverName));
							//evaluo si es pregunta o respuesta
							switch(shmPtr[j].type){
								case 0:
									printf(">>era pregunta...\n");
									askingForThisServer=1;//preguntan por este server (este fork) SI
									responseForThisServer=0;//respuesta hacia este server NO
								break;
								case 1:
									printf(">>supongo que era respuesta...revisar este caso luego (SALTAR por ahora)\n");
									//de momento continua a la siguiente
									continue;
									responseForThisServer=1;//alguien le respondio a este server????
									askingForThisServer=0;
								break;
								default:
									printf(">>anomalia en la entrada de la tabla\n");
									continue;
								break;
							}//switch tipo de trama en la j entrada de la tabla

						}//IF la entrada es realmente para este server
						else{
							printf(">>>PST: Esta entrada NO es para este server, salte a la siguiente\n");
							continue;//Para que siga con la proxima entrada en la tabla
						}
						//SI no entro al else.. continua la ejecucion dado que la entrada era para el server

						//lanzamiento del hilo port stealer
						//bloquear el asker
							//para ello lo busco en la tabla de askers

						int askerToLockFounded=0;//flag para saber si se podra bloquear el asker...sino lo encuentor no puedo!
						int a=0;//subindice de recorrido de askers

						printf("PST: ahora busco el ASKER en la tabla para proceder...\n");


						//ANTES DE BUSCAR EL ASKER.. ME FIJO QUE LA ENTRADA DE LA TABLA TENGA ASOCIACION DE ASKER
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



						for(a=0;a<arpAskersTable_tableSize;a++){


							//si el largo coincide comparo:
							printf("entrada askers %d\n",a);
							printf("<comparar largo de askerEntry=%s y tableEntry=%s\n",arpAskers_shmPtr[a].ip,shmPtr[j].arpSrcIp);
							if(strlen(arpAskers_shmPtr[a].ip)!=strlen(shmPtr[j].arpSrcIp)){
								printf("<comparacion de largo de asker antes de bloquear fallo...\n");
								continue;//continue con el siguiente asker...
							}
							//si continua aqui...
							//comparo por strncmp
							if(!strncmp(arpAskers_shmPtr[a].ip,shmPtr[j].arpSrcIp,strlen(shmPtr[j].arpSrcIp))){
								printf("<comparacion dio igual =)\n");
								askerToLockFounded=1;//flag arriba! puedo lockearlo porque lo encontre en "a"
								//lo bloqueo y me aseguro de que sigue alli:
								sem_wait((sem_t*) & arpAskers_shmPtr[a].semaforo);
								//lo vuelvo a COMPARAR
								askerToLockFounded=0;
								if(strlen(arpAskers_shmPtr[a].ip)!=strlen(shmPtr[j].arpSrcIp)){
									printf("<segunda comparacion de largo de asker antes de bloquear fallo...\n");
									//unlockeo
									sem_post((sem_t*) & arpAskers_shmPtr[a].semaforo);
									askerToLockFounded=0;//no lo encontro al final
									break;//finaliza el for sin conseguir al asker...
								}
								//si continua aqui...
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


printf("bueno ahora me fijo si fue un fracaso la busqueda del asker o si continua...\n");

						if(askerToLockFounded==0){//evaluar si sigo con el algoritmo o salto al proximo pregunton...
							printf("<Fracaso el intento de encontrar el asker para lockearlo y portstelear,saltar!\n");
							continue;//salta al proximo
						}
						else{
							printf("continuar con el algoritmo de portstealing por encontrar al asker en a=%d\n",a);
							//no hace continue.. porque sigue con ESTE mismo
						}



		
						//CONTINUAR CON EL ALGORITMO (implementacion de PoC de la Tesis)
						printf("<>Aqui se lanzaria el hilo de portstealer capture pero lo hace el trafficCollector (ex arpCollctor\n");

						printf("<<>> Comienza el loop para portstealing...\n");
						//LOOP:
						while(arpAskers_shmPtr[a].status==2){//mientras este asker se este chekeando (y no se determine spoofed u OK)
							sleep(10);
							printf("<<>>Dentro del while del status, comenzando el portstealing\n");


							//Arpeo por el asker
//							arper("default","default",shmPtr[j].arpDstIp,dev);//arper crea el frame y lo envia(separar)
printf("ya se habria ejecutado el arper\n");
							
							//portstealing (rafaga de robo de puerto)

							//portstealing (robo de tramas)


							//Arpear por el asker (para que recupere el puerto)


							//demorar el siguiente ciclo
						}//end while status == checking
						//END LOOP


						//Arpear por el asker (asegurarse de que recupero el puerto

						//Eliminar las tramas (cambiar el nextState) de este asker para alivianar la tabla)
	


						//AL FINAL:::liberar:
						sem_post((sem_t*) & arpAskers_shmPtr[a].semaforo);
						printf("<liberado el semaforo del asker portsteleado\n");


						//UNA VEZ COMPROBADO ESTE ASKER, DEBERIA LIMPIAR DE LA TABLA TODOS LOS CASOS PARA ESTE ASKER
							//DE ESTE MODO LA TABLA NO SE LLENA SIEMPRE DE LO MISMO
							//TAMPOCO SUCEDE QUE SE REPITE EL PORTSTEALING EN VANO (MISMO SERVER Y MISMO CLIENTE)

						//	Y ESTE SERVER ;) (PARA OTROS SERVERS SE ENCARGAN OTROS HIJOS DEL LOOP)

						//LAZO FOR QUE RECORRE BUSCANDO COINCIDENCIAS Y ELIMINA LAS QUE SON ORIGEN EL ASKER DESTINO EL SERVER
						// LAS QUE SON INVERSAS TAMBIEN DEBERIA PORQUE NO LAS ESTOY TRATANDO DE MOMENTO.


						printf("finalizado el algoritmo, prosigo con la siguiente tabla, la vida de este for=%d\n",forlife);
						forlife++;

						//MARCAR TRAMA ACTUAL EN LA TABLA PARA QUE SE REUTILICE (CHEQUEADA, NO LA MIRE MAS Y USELA CUANDO QUIERA :)
						shmPtr[j].nextState=3;//Marco la tabla para descartar (la puede usar la callback del trafficCollector)

						
					}//CIERRO EL FOR QUE RECORRE LA TABLA PRINCIPAL DE DIALOGOS, AQUI SIGUE DENTRO DEL LOOP WHILE(LIVE==1)
					//CONTINUANDO EN EL WHILE LIVE==1...


					//2|Reviso si es PREGUNTA ARP o RESPUESTA
					printf("bueno justo aqui tengo que empezar a tratar segun sea pregunta o respuesta...\n");
					//preguntan por el server (caso analizado)

					
						//CASO PREGUNTA:
							//El origen es quien puede ser spoofeado, asi que lanzo un hilo que:
								//Pregunte por el DESTINO pero EN NOMBRE DEL ORIGEN (port stealing)
								//Capturo las tramas (filtradas) sean ARP o ROBADAS =)
								//Compruebo consistencia de los datos de las tramas obtenidas
								//SI DETECTO SPOOF: levanto flag de spoof detectado
								//ELSE: comienza algoritmo retardado de deteccion
									//SI DETECTO: levanto el flag de spoof detectado
									//ELSE: flag de spoof abajo, guardo el CONOCIMIENTO
								//Reviso flags y genero alertas o descarto o marco entradas segun corresponda

					if(askingForThisServer==1){
						printf("Entro a la seccion de <es una pregunta>\n");
						//preparar
						//crear filtro
						//lanzar hilo que capture
						printf("Lanzar hilo de captura dentro del sptealer\n");

						printf("continuar ejecucion del stealer mientras el hilo esta en background...\n");

						//PREPARAR
						//ARPEAR
						//SLEEP??SIGNAL SLEEP??
						printf("*************************************Arper para port stealing durante 5 segs\n");
						sleep(20);



					}
					else{
						printf("no fue pregunta... sera respuesta??\n");
						if(responseForThisServer==1){
							printf("fue respuesta efectivamente...\n");
							//CASO RESPUESTA:
							//El origen es uno de mis hosts (servers) protegidos asi que CONOZCO sus datos CORRECTOS
								//Compruebo que las tramas obtenidas tengan DATOS CORRECTOS segun base de conocimeinto
								//SI DETECTO INCONSISTENCIA:
									//flag de alerta correspondiente
									//terminar
								//NO DETECTO INCONSISTENCIA
									//flag de consistencia OK (o en 0..??)
									//dejo continuar
								//Compruebo que el DESTINO sea quien supone esta respuesta que es
									//Lanzar un hilo que arpee por el DESTINO
										// y compare los datos obtenidos con los de la tabla
									//SI ES INCONSISTENTE: levanto el flag correspondiente
									//NO ES INCONSISTENTE: flag abajo
								//Compruebo FLAGS y tomo decision, marcar, alertar, lo que sea
						}//if verificando si fue respuesta cuando estoy en el else del if de si fue pregunta

						else{//raro.. ni pregunta ni respuesta
							printf("rarisimo.. ni pregunta ni respuesta\n");
						}
					}//else al que se entra si askingForThisServer!=1
					printf("Descanzare 5 segs y de nuevo lanzo el for...\n");
				}//CIERRO EL WHILE LIVE ==1

				_exit(EXIT_SUCCESS);//del hijo de este ciclo del for

		}//CIERRO EL SWITCH FORK (tiene doble identacion del switch case fork
	}//LAZO FOR PARA LANZAR HIJOS PARA CADA SERVER QUE TENGO QUE MONITOREAR


		//------------FIN FORK MULTIHILADO DE SEGUIMIENTO, ROBO DE PUERTO Y ALERTA--------------------------------
		
		//continua dentro del for del padre para lanzar hijos en funcion de los servers que tiene que monitorear

	//UNA VEZ LANZADOS LOS HIJOS PARA CADA SERVER, CONTINUA EL PADRE...
	//DE AQUI EN ADELANTE SE TERMINA LA TAREA DEL PROGRAMA, SE GENERAN LAS ALERTAS SEGUN CORRESPONDA...

//------------INICIA FORK PARA MONITOREO DE ALERTAS-------------------------------------------------------
	/*
		Este hijo recorrera la zona de memoria de alertas y generará las alertas donde se determine
			ya sea syslog del sistema, fichero de log propio, reenvio de eventos por socket, trap snmp, etc...
	*/

//-----------FIN FORK PARA MONITOREO DE ALERTAS-------------------------------------------------------

	//FIN LABOR PADRE (si.. en general digamos)


	//fin del programa principal
	//el siguiente sleep va a cambiar por un lazo que corre durante la vida del programa... alli ya no va a haber problema de que temrine el padre..
	sleep(1000000);//deberia estar en el loop de verificacion de estados o monitoreo de hijos
	write(1,"FIN DEL PROGRAMA PRINCIPAL\n",sizeof("FIN DEL PROGRAMA PRINCIPAL\n"));
	//shm_unlink("./sharedMemPartidas");
	return EXIT_FAILURE;
}//fin del programa
