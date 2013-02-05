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
	//variables de datos del programa principal
//	char *mac2guard;//argumento que evolucionara a array y que representa todos los hosts protegidos
	//char *mac2guardIP //serian las ips que acompaña a las macs que van en mac2guard, para futuras versiones
//	int *power=0;//este comando va a evolucionar, representa uno de los parametros de FUERZA (repeticion) del port stealer o arper.
//	char* target;//propenso a desaparecer, dado que el target sera cualquier IP que pregunte por un mac2guard
//	char* iface;//voy a conservarlo, es el nombre de la interfaz de red que quiero utilizar
	//ojo abajo: en el caso del mac2guard lo hace dentro del arper a esto XD con el strcpy XD
//	char arperIface[10];//por problema que no reconoce el arper el argumento a no ser que sea hardcodeado
//	char arperTarget[15];//por lo mismo que con el anterior

	//parser(argv[1], &mac2guard, &power, &target, &iface);

	//printf("\nVariables seteadas por el parser: \nMAC: %s\nTARGET: %s\nIFACE: %s\n",mac2guard,target,iface);
	//int i=0;
	//aqui abajo la magia de la que hablaba en la definicion de variables...
//	strcpy(arperIface,iface);
//	strcpy(arperTarget,target);
	//segun el parametro power, son las veces que enviare frames
	//mas adelante, debo separar la creacion del frame del envio del mismo para no repetir tooooodo por cada iteracion


//------------INICIA ZONA DE DEFINICION DE ESTRUCTURAS DE DATOS DEL SABUESO--------------

/*
struct arpDialog{
        int index;
        char* etherSenderMac;
        char* etherDestinationMac;
        char* arpSenderMac;
        char* arpDestinationMac;
        char* arpSenderIp;
        char* arpDestinationIp;
        int hit;
	sem_t semaforo;
};
*/

//Crear zona de memoria compartida para alojar la estructura (o.. array de estructuras)

	//puntero a la memoria compartida
//	unsigned* shmPtr;
	struct arpDialog* shmPtr;
	//descriptor de la memoria compartida
	int fdshm;
	//sharedMem
	int subindexCounterId = 0;//es para indizar (o dar ID) a cada entrada de la tabla
	struct arpDialog arpDialoguesTable[100];//hardcodeado, luego deberia parametrizarlo y variabilizarlo
	for(subindexCounterId=0;subindexCounterId<100;subindexCounterId++){//ese 100 es el hardcodeado anterior
		arpDialoguesTable[subindexCounterId].index=subindexCounterId;
		//int sem_init(sem_t *sem, int pshared, unsigned int value);
		sem_init(&(arpDialoguesTable[subindexCounterId].semaforo),1,1);//inicializa semaforos de cada entrada de la tabla
	}//inicializadas las entradas de la tabla, paso a confeccionar la Memoria Compartida


	//SHAREDMEMrpDialoguesTableManagerArguments.h

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
	if(!(shmPtr=mmap(NULL, sizeof(struct arpDialog)*100, PROT_READ|PROT_WRITE, MAP_SHARED, fdshm, 0))){
		perror("mmap()");
		exit(EXIT_FAILURE);
	}
	//la truncada de suerte!!:
	ftruncate(fdshm, sizeof(struct arpDialog)*100);
	close(fdshm);

	//una vez que tengo el puntero a la zona de memoria... lo probamos
/*
	printf("sin puntero, solo estructura: indice del 43°= %d\n",arpDialoguesTable[43].index);
	printf("ahora utilizando el puntero:  indice del 43°= %d\n",(int) shmPtr[43].index);//perfecto
*/


	//Test de semaforo desde el main
/*
	sem_wait( (sem_t*)&(shmPtr[43].semaforo));
	printf("obtuve el semaforo\n");
	sem_post( (sem_t*)&(shmPtr[43].semaforo));
	printf("he soltado el semaforo\n");
*/
	//VARS
	//int o;//para los for de los wait y post (pruebas de semaforos)
	//TABLES
	//ETC...



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

//---------------INICIA FORK DE CONFIGURACION Y CHEQUEO DE TABLA DE DIALOGOS ARP-----------------------------

        switch(fork()){
                case -1:
                        perror("fork()");
                        _exit(EXIT_FAILURE);
                case 0:
                        puts("\nxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");
                        puts("soy el HIJO manejador y centinela de tabla arpDialoguesTable...\n");
                        //preparo para leer el PIPE, y luego lanzo los hilos para cada paquete leido
                        //cierro escritura, solo voy a leer.
                        close(fdPipe[1]);
                        //variable para el paquete leido
                        char bufl[4096];
                        //hebras del admin de partidas
                        pthread_t hilo;
                        pthread_attr_t attr;
                        pthread_attr_init (&attr);
                        pthread_attr_setdetachstate (&attr, PTHREAD_CREATE_JOINABLE);
                        //n como contador de lo que se leyo
                        int n=0,k=0,paquete=0;
			//printf("hola\n");
			arpDTMWorker_arguments arguments[2];
//			arguments[0].shmPtr=shmPtr;
			while((n=read(fdPipe[0], bufl, sizeof bufl))){
				paquete++;
				puts("lei del pipe\n");
				bufl[n]=0;
				
				if(strlen(bufl)!=0){
					puts("parece que el primer HIJO leyo lo siguiente: ");

					if(!(write(0, bufl, strlen(bufl)))){
						perror("write()");
						exit(EXIT_FAILURE);
					}
				printf("HILO paquetes: %d\n",paquete);
				}
					puts("\n\n");
					k=0;
					//llamo a la funcion splitter:
					char **listSplit;
					listSplit = splitter(bufl,'|');
					free(**listSplit);
					/*
					while (listSplit[k]!=NULL){
						switch(k){
							case 0:
								printf("k=0, luego valor=%s\n",listSplit[k]);
								arguments[0].ethSrcMac=listSplit[k];
								printf("para ethSrcMac tengo el valor=%s\n",arguments[0].ethSrcMac);

							break;
							case 1:
								printf("k=1, luego valor=%s\n",listSplit[k]);
								arguments[0].ethDstMac=listSplit[k];
								printf("para ethDstMac tengo el valor=%s\n",arguments[0].ethDstMac);


							break;
							case 2:
								printf("k=2, luego valor=%s\n",listSplit[k]);
								arguments[0].arpSrcMac=listSplit[k];
								printf("para arpSrcMac tengo el valor=%s\n",arguments[0].arpSrcMac);

							break;
							case 3:
								printf("k=3, luego valor=%s\n",listSplit[k]);
								arguments[0].arpDstMac=listSplit[k];
								printf("para arpDstMac tengo el valor=%s\n",arguments[0].arpDstMac);


							break;
							case 4:
								printf("k=4, luego valor=%s\n",listSplit[k]);
								arguments[0].arpSrcIp=listSplit[k];
								printf("para ethSrcIp tengo el valor=%s\n",arguments[0].arpSrcIp);
							break;
							case 5:
								printf("k=5, luego valor=%s\n",listSplit[k]);
								arguments[0].arpDstIp=listSplit[k];
								printf("para arpDstIp tengo el valor=%s\n",arguments[0].arpDstIp);
							break;

							default:
							break;
						}
						//listSplit[k++];//si comento esta linea, se joroba TODO!! ¿¡por queeee?!
						printf("salio:%s\n" , listSplit[k++]);
					}
					//Mostrar el bufl crudo, como lo leyo del pipe..medio tarde pero deberia estar intacto
					//printf("leiiiiiiii %s\n",bufl);

					arguments[0].packet="|hola|como|estas|pedazo|de|gil|";
					//printf("a modo de ejemplo muestro ethDstMac en a1= %s\n",arguments[0].ethDstMac);
					//deberia controlar la creacion de HILOS.. algun limite..sino dice que no puede allocar mas memoria
					if(pthread_create(&hilo, &attr, arpDialoguesTableManager, &arguments)){
                                                perror("pthread_create()");
                                                exit(EXIT_FAILURE);
						//continue;
                                        }
					//lanzado el hilo..comienza de nuevo
					printf("PAQUETE AL HILO : %d\n",paquete);
					
                                }*/
                        }
                        _exit(EXIT_SUCCESS);
                }//switch fork
//---------------FINALIZA FORK DE CONFIGURACION Y CHEQUEO DE TABLA DE DIALOGOS ARP-----------------------------


//Continua el hilo principal de ejecucion....



//---------------INICIA FORK PARA RECOLECCION DE ARP EN EL BROADCAST O MODULO ARPCOLLECTOR-----------------------------

	/*
				arpCollector.c

		En este punto tenemos la zona de memoria y los elementos de ipc y control
		Procedo al forkeo para iniciar un proceso encargado de monitorear la existencia
		De "preguntas" ARP al broadcast, luego la funcion de callback se encargara de tratar al paquete:


		Configurar FILTRO para ARP solamente (requests?) y para los hosts que me interesan??
		

			Primero calcula el hash identificador del dialogo: macIpOrigen;macIpDestino
			Si existe en la tabla
				Disminuye un hit en la tabla? o pone un valor de cantidad de msjs vistos

			Si NO existe en la tabla:
				por cada TRAMA con Mensaje ARP extraer y guardar:
					Mac Origen de la trama
					Mac Destino de la trama
					Mac Origen del msj ARP
					IP Origen del msj ARP
					Mac destino del msj ARP
					IP destino del msj ARP
					Calcular:
						hash del conjunto macIpOrigen;macIpDestino (para idizar el dialogo univocamente)
						hash del Sender: macIpOrigen
						hash del Destino: macIpDestino
				La "tabla" construida con registros de este "tpo" es la base para disparar los hilos de monitoreo
				retornar al bucle
			continuar bucle

		*/

	switch(fork()){
		case -1:
			perror("fork()");
			_exit(EXIT_FAILURE);
		case 0:
			//Proceso arpCollector.c
			puts("\n-------------------------");

			puts("soy el HIJO recolector de mensajes ARP iniciando...\n");
			//test delay con semaforo:
			/*
			for(o=0;o<10;o++){
				sem_wait( (sem_t*)&(shmPtr[43].semaforo));
				printf("ahora EL HIJO en el 43°= %d\n",(int) shmPtr[43].index++);//perfecto
				sem_post( (sem_t*)&(shmPtr[43].semaforo));
				//sleep(1);
			}
			*/


			//COmienza a preparar la captura...
			char* dev=NULL;
			char errbuf[PCAP_ERRBUF_SIZE];
			pcap_t* descr;//descriptor de la captura
			struct bpf_program fp;//aca se guardara el programa compilado de filtrado
			bpf_u_int32 maskp;// mascara de subred
			bpf_u_int32 netp;// direccion de red
			//el IF de abajo no tiene nada que hacer aqui!!! que modo de uso ni que changos!!
			if (argc != 2){
				fprintf(stdout,"Modo de Uso %s \"programa de filtrado\"\n",argv[0]);
				return 0;
			}
			dev = pcap_lookupdev(errbuf); //Buscamos un dispositivo del que comenzar la captura
                        printf("\nEcontro como dispositivo %s\n",dev);
                        if (dev == NULL){
                                fprintf(stderr," %s\n",errbuf); exit(1);
                        }
                        else{
                                printf("Abriendo %s en modo promiscuo\n",dev);
                        }
                        dev = "wlan0";//hardcodeo la wifi en desarrollo
			//obtener la direccion de red y la netmask
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
				{1, "Argumentos",shmPtr}
			};
			//le paso los descriptores del PIPE
			conf[0].fdPipe[0]=fdPipe[0];
			conf[0].fdPipe[1]=fdPipe[1];

			pcap_loop(descr,-1,(pcap_handler)arpCollector_callback,(u_char*) conf);

			_exit(EXIT_SUCCESS);
	}//FIN DEL FORK PARA ARPCOLLECTOR


//---------------FIN FORK PARA RECOLECCION DE ARP EN EL BROADCAST O MODULO ARPCOLLECTOR-----------------------------

//CONTINUA EL HILO DE EJECUCION...



//preparar creacion de hijo multihilado responsable del port stealing y alerta

//------------INICIA FORK MULTIHILADO DE SEGUIMIENTO, ROBO DE PUERTO Y ALERTA-----------------------------
	/*
		Este hijo se va a encargar de recorrer la tabla base de dialogos arp
			Si no hay elementos en la tabla:
				Esperar que no hayan hilos dependientes
				Pausa
				continuar
	
			Por cada entrada con hit:
			mayor igual a 1:
				Lanza hilo de monitoreo
					El hilo hace portstealing
					Captura
					Comprueba cabeceras eth y ip, compara datos con la tabla
						Si hay ambiguedad:
							Devuelve el puerto
							Generar alerta
							Eleva el hit 3? puntos arriba
						Else
							Eleva el hit 1 punto mas (los puntos determinan la fuerza del portstealing)
					fin, retorna control al proceso
				Continuar
			igual a 0:
				Lanza hilo de mantenimiento de tabla
					Mover el dialogo a la base de dialogos conocidos
					O podria ser Eliminar el dialogo de la tabla
				retornar
			Continuar
		Reiniciar(loop en la tabla)

	*/
//------------FIN FORK MULTIHILADO DE SEGUIMIENTO, ROBO DE PUERTO Y ALERTA--------------------------------

//Proceso padre, monitoreo de los hijos
//Preparo para monitorear ALERTAS

//------------INICIA FORK PARA MONITOREO DE ALERTAS-------------------------------------------------------
	/*
		Este hijo recorrera la zona de memoria de alertas y generará las alertas donde se determine
			ya sea syslog del sistema, fichero de log propio, reenvio de eventos por socket, trap snmp, etc...
	*/

//-----------FIN FORK PARA MONITOREO DE ALERTAS-------------------------------------------------------



//FIN LABOR PADRE (si.. en general digamos)


//---------------------seccion de port stealing----------------
// esto tiende a mudarse a otra parte del codigo, seria lo que hacen los hilos para monitorear un dialogo	
/*
	for(i=0;i<power;i++){
//		arper(mac2guard,arperIface,arperTarget);//arper crea el frame y lo envia(separar)
		arper("00:21:5c:33:09:a5",arperIface,arperTarget);//arper crea el frame y lo envia(separar)
	sleep(1);
	}
*/
//--------------------fin port stealing-----------------------
/*
	for(o=0;o<100;o++){
		sem_wait( (sem_t*)&(shmPtr[43].semaforo));
		printf("ahora EL PADRE en el 43°= %d\n",(int) shmPtr[43].index++);//perfecto
		sem_post( (sem_t*)&(shmPtr[43].semaforo));
		//sleep(2);
	}
*/
	//fin del programa principal
	sleep(10000);
	write(1,"FIN DEL PROGRAMA PRINCIPAL\n",sizeof("FIN DEL PROGRAMA PRINCIPAL\n"));
	//shm_unlink("./sharedMemPartidas");
	return EXIT_FAILURE;
}
