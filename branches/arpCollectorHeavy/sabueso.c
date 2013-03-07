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
#include "arper.h"
//#include "parser.h"
#include "splitter.h"
#include "arpDialogStruct.h"
#include "arpCollector_callback.h"
#include "callbackArgs.h"

#include "arpDialoguesTableManager.h"
#include "arpDialoguesTableManagerArguments.h"
//#include "arpDTMWorker_arguments_struct.h"

//MENSAJES ESTATICOS
#define MSG_START "Comienza aqui el programa principal\n"



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
	int retorno = shm_unlink("/sharedMemPartida");
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

//------------INICIA ZONA DE DEFINICION DE ESTRUCTURAS DE DATOS DEL SABUESO--------------
	//vida de los hijos
	int live=1;

	//Crear zona de memoria compartida para alojar la estructura (o.. array de estructuras)

	//puntero a la memoria compartida
	struct arpDialog* shmPtr=NULL;
	//descriptor de la memoria compartida
	int fdshm;
	//sharedMem
	int subindexCounterId = 0;//es para indizar (o dar ID) a cada entrada de la tabla
	int tableSize=10;
	struct arpDialog arpDialoguesTable[tableSize];//hardcodeado, luego deberia parametrizarlo y variabilizarlo
	//inicializacion:
	for(subindexCounterId=0;subindexCounterId<tableSize;subindexCounterId++){//ese 100 es el hardcodeado anterior
		arpDialoguesTable[subindexCounterId].index=subindexCounterId;
		arpDialoguesTable[subindexCounterId].ethSrcMac=NULL;
		arpDialoguesTable[subindexCounterId].ethDstMac=NULL;
		arpDialoguesTable[subindexCounterId].arpSrcMac=NULL;
		arpDialoguesTable[subindexCounterId].arpDstMac=NULL;
		arpDialoguesTable[subindexCounterId].arpSrcIp=NULL;
		arpDialoguesTable[subindexCounterId].arpDstIp=NULL;
		arpDialoguesTable[subindexCounterId].type=NULL;
		arpDialoguesTable[subindexCounterId].doCheckIpI=0;
		arpDialoguesTable[subindexCounterId].doCheckSpoofer=0;
		arpDialoguesTable[subindexCounterId].doCheckHosts=0;
		arpDialoguesTable[subindexCounterId].nextState=4;
		arpDialoguesTable[subindexCounterId].hit=0;
		//int sem_init(sem_t *sem, int pshared, unsigned int value);
		sem_init(&(arpDialoguesTable[subindexCounterId].semaforo),1,1);//inicializa semaforos de cada entrada de la tabla
	}//inicializadas las entradas de la tabla, paso a confeccionar la Memoria Compartida

	//return;//ES PARA MOSTRAR EL PROBLEMA QUE TENGO AQUI.. SERA PORQUE NO ESTOY MALLOCANDO???

	//por debug, inicializo el 43 con el hit = 5;

	arpDialoguesTable[4].hit=5;
/*
	arpDialoguesTable[0].nextState=3;
	arpDialoguesTable[1].nextState=3;
	arpDialoguesTable[2].nextState=3;
	arpDialoguesTable[7].nextState=3;
	arpDialoguesTable[9].nextState=3;
*/
	

	

	
	//SHAREDMEM arpDialoguesTableManagerArguments.h
	if(((fdshm=shm_open("/sharedMemPartida", O_RDWR|O_CREAT, 0666))<0)){
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
			char* dev=NULL;
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
			pcap_lookupnet(dev,&netp,&maskp,errbuf);
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
			//Argumentos para la funcion callback
			arpCCArgs conf[2] = {
			//	{0, "foo",shmPtr},
				{tableSize, "Argumentos",shmPtr}
			};
			//le paso los descriptores del PIPE
			conf[0].fdPipe[0]=fdPipe[0];
			conf[0].fdPipe[1]=fdPipe[1];
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

	//cantidad de servers a cuidar:
	int serversQuantity=4;

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

	int j=0;//otro subindice
	for(i=0;i<serversQuantity;i++){
		//------------INICIA FORK MULTIHILADO DE SEGUIMIENTO, ROBO DE PUERTO Y ALERTA-----------------------------
		switch(fork()){
			case -1:
				perror("fork()");
				_exit(EXIT_FAILURE);
			case 0:
				//Proceso arpCollector.c
				printf("soy el HIJO PORT STEALER del host: %s\n",(servers2guard[i].serverName));

				//flags:
				int askingForThisServer=0;//inicializa en "no preguntan por el server"
							
				//ALGORITMO:
				//1|Examinar entrada por entrada de la tabla y para cada una:
				live=1;
				j=0;
				while(live==1){
					sleep(20);//descanza 20 segundos despues de cada recorrida completa
					for(j=0;j<tableSize;j++){
						//por las dudas me fijo si la entrada en la tabla no es NULL:
						if(arpDialoguesTable[j].arpDstIp==NULL){

							printf("<<Entrada vacia, continuar con la siguiente\n");
							continue;
						}
						//else...
						//1.99 Si esta involucrado ESTE server:

						//si es destino
						if(!strcmp(servers2guard[i].ip,arpDialoguesTable[j].arpDstIp)){//si la ip por la q se pregunta es del server i
							printf(">>>Esta entrada de la tabla esta destinada al server %s\n",(servers2guard[i].serverName));
							//evaluo si es pregunta o respuesta
							switch(arpDialoguesTable[j].type==0){
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
							if(!strcmp(servers2guard[i].ip,arpDialoguesTable[j].arpDstIp)){
								printf(">>>Esta entrada fue ORIGINADA por el server %s\n",(servers2guard[i].serverName));
								//tratar este segmento del codigo luego..
							}
							else{//no esta involucrado el server i
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
				_exit(EXIT_SUCCESS);//del hijo de este ciclo del for
		}//CIERRO EL SWITCH FORK
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
