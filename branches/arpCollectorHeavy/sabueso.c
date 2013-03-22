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


//MIS PROPIAS CABECERAS
//#include "sabueso.h"
//#include "arper.h" //LO SAQUE POR DESUSO Y PARA LIMPIAR UN POCO DE CODIGO
//#include "parser.h"
//#include "splitter.h" //LO SAQUE POR DESUSO Y PARA LIMPIAR UN POCO DE CODIGO
#include "arpDialogStruct.h"
//#include "arpAskerStruct.h"
#include "arpCollector_callback.h"
#include "callbackArgs.h"

//#include "arpDialoguesTableManager.h"//se removio de este branche.. tarde pero se removio
//#include "arpDialoguesTableManagerArguments.h" //y si.. tambien se removio este por supuesto
//#include "arpDTMWorker_arguments_struct.h"

//MENSAJES ESTATICOS
#define MSG_START "Comienza aqui el programa principal\n"

//MACROS DE ARGS
#define TABLE_SIZE 4

//Icludes del arpCollector.c
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

	//manejador SIGTERM
	signal(SIGINT , sigint_handler);

	if(0>=write(1,MSG_START, strlen(MSG_START)))
		return -1;
	int i=0;//indice utilizando en los for...
//------------INICIA ZONA DE CONTROL DE PARAMETROS DE APLICACION-----------------------------------------------//

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
	//ahora compilo el programa de filtrado para hacer un filtro para ARP
	if(pcap_compile(descr,&fp,"arp",0,netp)==-1){//luego lo cambiare para filtrar SOLO los mac2guards
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



	//INICIA CREACION DE TABLA DE DIALOGOS

	//Crear zona de memoria compartida para alojar la estructura (o.. array de estructuras)

	//puntero a la memoria compartida
	struct arpDialog* shmPtr=NULL;
	//descriptor de la memoria compartida
	int fdshm;
	//sharedMem
	int subindexCounterId = 0;//es para indizar (o dar ID) a cada entrada de la tabla
//	int tableSize=(arpAskersTable_tableSize*arpAskersTable_tableSize)/2;//maximo de preguntas ARp permitidas por el tamaño de la red
	int tableSize=TABLE_SIZE;
	//malloqueo para el puntero de la shm
	shmPtr = (struct arpDialog *)malloc(sizeof(struct arpDialog)*TABLE_SIZE);
	struct arpDialog arpDialoguesTable[tableSize];//CONSULTAR: AQUI NO DEBERIA MALLOQUEAR?? COREDUMP SI TABLESIZE ES MUY GRANDE!!
	//inicializacion:
	for(subindexCounterId=0;subindexCounterId<tableSize;subindexCounterId++){//ese 100 es el hardcodeado anterior
		arpDialoguesTable[subindexCounterId].arpAskerIndex=subindexCounterId;
		arpDialoguesTable[subindexCounterId].ethSrcMac=NULL;
		arpDialoguesTable[subindexCounterId].ethDstMac=NULL;
		arpDialoguesTable[subindexCounterId].arpSrcMac=NULL;
		arpDialoguesTable[subindexCounterId].arpDstMac=NULL;
		memset(arpDialoguesTable[subindexCounterId].arpSrcIp,0,40);
		arpDialoguesTable[subindexCounterId].arpDstIp=NULL;
		arpDialoguesTable[subindexCounterId].type=99;//0 es pregunta, 1 es respuesta, 99 inicializada
		arpDialoguesTable[subindexCounterId].doCheckIpI=0;
		arpDialoguesTable[subindexCounterId].doCheckSpoofer=0;
		arpDialoguesTable[subindexCounterId].doCheckHosts=0;
		arpDialoguesTable[subindexCounterId].nextState=4;
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
		arpAskersTable[subindexCounterId].mac=NULL;
		arpAskersTable[subindexCounterId].ip=NULL;
		arpAskersTable[subindexCounterId].status=NULL;
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
	//defino el PIPE que voy a utilizar con el HIJO multihilado que chekea la informacion ANTES de guardarla
	int fdPipe[2];
        if(pipe(fdPipe)==-1){
                perror("Problema con el pipe");
                exit(EXIT_FAILURE);
        }
//------------FIN DEFINICION DE ELEMENTOS DE IPC, CONCURRENCIA Y EXCLUSION----------------


//---------------INICIA FORK PARA RECOLECCION DE ARP EN EL BROADCAST O MODULO ARPCOLLECTOR-----------------------------
	switch(fork()){
		case -1:
			perror("fork()");
			_exit(EXIT_FAILURE);
		case 0:
			//Proceso arpCollector.c
			puts("\n-------------------------");
			puts("soy el HIJO recolector de mensajes ARP iniciando...\n");
	
			//COmienza a preparar la captura...
			dev=NULL;
			net=NULL;
			mask=NULL;
			//Argumentos para la funcion callback
			arpCCArgs conf[2] = {
			//	{0, "foo",shmPtr,arpAskers_shmPtr},
				{tableSize, "Argumentos",shmPtr,arpAskers_shmPtr,arpAskersTable_tableSize}
			};
			//le paso los descriptores del PIPE
			conf[0].fdPipe[0]=fdPipe[0];
			conf[0].fdPipe[1]=fdPipe[1];
			//El bucle de captura lo armo con variables que el padre ya preparo antes cuando hizo el check de la netmask
			pcap_loop(descr,-1,(pcap_handler)arpCollector_callback,(u_char*) conf);
			_exit(EXIT_SUCCESS);
	}//FIN DEL FORK PARA ARPCOLLECTOR


//---------------FIN FORK PARA RECOLECCION DE ARP EN EL BROADCAST O MODULO ARPCOLLECTOR-----------------------------

	//Continua el padre...
	//ahora recorrer el array de servers que tengo que "cuidar" (monitorear)
	//Recordemos que cada host que tenga interes en hablar con estos servers (que tienen informacion sensible) son
	//posibles victimas de ataques arp spoofing.
	//Ahora lo que voy a hacer, es por cada uno de los hosts a monitorear lanzar un HIJO con la funcion correspondiente.

	//----VOY A HARDCODEAR LOS PARAMETROS DE MOMENTO:

	int serversQuantity=5;//cantidad de servers a cuidar

	//Estructura de datos de argumentos del programa principal
	typedef struct{ 
                char *mac;
                char *ip;
		char *serverName;
                int serviceType;//0 http,1 rdp
        }server2guard;

	server2guard servers2guard[serversQuantity];//array de servers

	//inicializar array de struct:
	for(i=0;i<serversQuantity;i++){
		servers2guard[i].mac=NULL;
		servers2guard[i].ip=NULL;
		servers2guard[i].serviceType=0;
		servers2guard[i].serverName=NULL;
	}
	//invento hosts

	servers2guard[0].mac="aa:bb:cc:dd:ee:f";
	servers2guard[0].ip="192.168.1.121";
	servers2guard[0].serviceType=0;
	servers2guard[0].serverName="server-121";
	

	servers2guard[1].mac="12:43:56:a:a:2";
	servers2guard[1].ip="192.168.1.126";
	servers2guard[1].serviceType=0;
	servers2guard[1].serverName="server-126";

	servers2guard[2].mac="5c:d9:98:2c:0f:b6";
	servers2guard[2].ip="192.168.1.101";
	servers2guard[2].serviceType=0;
	servers2guard[2].serverName="thinkpad-101";

	servers2guard[3].mac="5c:d9:98:2c:f:b6";//seria 5c:d9:98:2c:0f:b6
	servers2guard[3].ip="192.168.1.1";
	servers2guard[3].serviceType=0;
	servers2guard[3].serverName="dd-wrt";

	servers2guard[4].mac="00:21:5c:33:09:a5";
	servers2guard[4].ip="192.168.1.101";
	servers2guard[4].serviceType=0;
	servers2guard[4].serverName="myself";


	int j=0;//otro subindice

	int c=0;

	serversQuantity=1;


				while(1==1){
					sleep(1);
					
					printf("mostrando memoria compartida desde el port stealer pasada %d\n",j);
					for(c=0;c<tableSize;c++){
						printf("entrada %d, arpSrcIp: %s \n",c,shmPtr[c].arpSrcIp);
/*
						write(1,"arpSrcIp \n",strlen("arpSrcIp "));
						write(1,(char *)(shmPtr[c].arpSrcIp),4);
						write(1,"\n",strlen("\n"));
*/

					}
					j++;
				}
sleep(100000);



	for(i=0;i<serversQuantity;i++){
		//------------INICIA FORK MULTIHILADO DE SEGUIMIENTO, ROBO DE PUERTO Y ALERTA-----------------------------
		switch(fork()){
			case -1:
				perror("fork()");
				_exit(EXIT_FAILURE);
			case 0:
				sleep(5);
				printf("soy el HIJO PORT STEALER del host: %s\n",(servers2guard[i].serverName));
				j=0;

//----------------------------------------
				//ACONDICIONAR SHAREDMEM DE DIALOGOS EN ESTE HIJO
/*
				if(((fdshm=shm_open("/sharedMemDialogos", O_RDWR|O_CREAT, 0666))<0)){
					perror("shm_open()");
					exit(EXIT_FAILURE);
				}
				if(!(shmPtr=mmap(NULL, sizeof(struct arpDialog)*tableSize, PROT_READ|PROT_WRITE, MAP_SHARED, fdshm, 0))){
					perror("mmap()");
					exit(EXIT_FAILURE);
				}
				//la truncada de suerte!!:
				ftruncate(fdshm, sizeof(struct arpDialog)*tableSize);
				close(fdshm);
*/

				while(1==1){
					sleep(10);
					
					printf("mostrando memoria compartida desde el port stealer pasada %d\n",j);
					for(c=0;c<tableSize;c++){
						printf("entrada %d, arpSrcIp: %s largo %d \n",c,shmPtr[c].arpSrcIp,(int)strlen(shmPtr[c].arpDstIp));
//						write(1,"arpSrcIp \n",strlen("arpSrcIp "));
//						write(1,(char *)(shmPtr[c].arpSrcIp),4);

					}
					j++;
				}




//------------------------------------------
/*

				//flags:
				int askingForThisServer=0;//inicializa en "no preguntan por el server"
							
				//ALGORITMO:
				//1|Examinar entrada por entrada de la tabla y para cada una:
				live=1;
				j=0;
				while(live==1){//podria ser un while true, se utilizo esta variable para tener condicion de corte (aunque puedo usar break...)
//					sleep(20);//descanza 20 segundos despues de cada recorrida completa
					for(j=0;j<tableSize;j++){
						//por las dudas me fijo si la entrada en la tabla no es NULL:
						if(shmPtr[j].arpDstIp==NULL){

							printf("<<Entrada vacia, continuar con la siguiente\n");
							continue;
						}
						else{
							printf("<<Esta entrada no esta vacia!!! ahora va al if de si coincide con el server que cuido...\n");
							printf("comparando i: %s con shmPtr: %s \n",servers2guard[i].ip,shmPtr[j].arpDstIp);
							continue;
						}
						//else...
						//1.99 Si esta involucrado ESTE server:

						//si es destino
						printf("comparando i: %s con shmPtr: %s \n",servers2guard[i].ip,shmPtr[j].arpDstIp);
						if(!strcmp(servers2guard[i].ip,shmPtr[j].arpDstIp)){//si la ip por la q se pregunta es del server i
							printf(">>>Esta entrada de la tabla esta destinada al server %s\n",(servers2guard[i].serverName));
							//evaluo si es pregunta o respuesta
							switch(shmPtr[j].type==0){
								case 0:
									printf(">>era pregunta...\n");
									askingForThisServer=1;
								break;
								case 1:
									printf(">>supongo que era respuesta...\n");
								break;
								default:
									printf(">>anomalia en la entrada de la tabla\n");
									continue;
								break;
							}//switch tipo de trama en la j entrada de la tabla

						}//server i es destino
						else{//si server i no es el destino sera el origen?
							if(!strcmp(servers2guard[i].ip,shmPtr[j].arpDstIp)){
								printf(">>>Esta entrada fue ORIGINADA por el server %s\n",(servers2guard[i].serverName));
								//tratar este segmento del codigo luego..
							}
							else{//no esta involucrado el server i
								printf(">>>OK no estaba vacia pero no involucraba al server %s\n",servers2guard[i].ip);
								continue;
							}
						}//else para que el server i sea el origen

						//2|Reviso si es PREGUNTA ARP o RESPUESTA
						
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
													
					}//lazo for que recorre las entradas de la tabla
				}//CIERRO EL WHILE LIVE ==1
*/
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
