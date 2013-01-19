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
#include "parser.h"
#include "arpDialogStruct.h"
#include "arpCollector_callback.h"
#include "callbackArgs.h"



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

//Aqui comienza la magia =)
int main(int argc, char *argv[]){
	if(0>=write(1,MSG_START, strlen(MSG_START)))
		return -1;
	//variables de datos del programa principal
	char *mac2guard;//argumento que evolucionara a array y que representa todos los hosts protegidos
	//char *mac2guardIP //serian las ips que acompaña a las macs que van en mac2guard, para futuras versiones
	int *power=0;//este comando va a evolucionar, representa uno de los parametros de FUERZA (repeticion) del port stealer o arper.
	char* target;//propenso a desaparecer, dado que el target sera cualquier IP que pregunte por un mac2guard
	char* iface;//voy a conservarlo, es el nombre de la interfaz de red que quiero utilizar
	//ojo abajo: en el caso del mac2guard lo hace dentro del arper a esto XD con el strcpy XD
	char arperIface[10];//por problema que no reconoce el arper el argumento a no ser que sea hardcodeado
	char arperTarget[15];//por lo mismo que con el anterior

	parser(argv[1], &mac2guard, &power, &target, &iface);

	printf("\nVariables seteadas por el parser: \nMAC: %s\nTARGET: %s\nIFACE: %s\n",mac2guard,target,iface);
	int i=0;
	//aqui abajo la magia de la que hablaba en la definicion de variables...
	strcpy(arperIface,iface);
	strcpy(arperTarget,target);
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
		//arpDialoguesTable[subindexCounterId].etherSenderMac=NULL;
		//todos los elementos....
		//int sem_init(sem_t *sem, int pshared, unsigned int value);
		sem_init(&(arpDialoguesTable[subindexCounterId].semaforo),1,1);//inicializa semaforos de cada entrada de la tabla
	}//inicializadas las entradas de la tabla, paso a confeccionar la Memoria Compartida


	//SHAREDMEM

	//int shmTotalBloks=100;//hardcodeado de antes..
	//int field=0,block=0,fieldValue=0;
	//int blockSize=(sizeof(int)+6*sizeof(char*)+sizeof(int)+sizeof(sem_t));
//	printf("EL TAMAÑO DE LA ESTRUCTURA: %d, y de la suma: %d\n", sizeof(arpDialoguesTable[0]), blockSize);

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
	close(fdshm);

	//una vez que tengo el puntero a la zona de memoria... lo probamos

	printf("sin puntero, solo estructura: indice del 43°= %d\n",arpDialoguesTable[43].index);
	printf("ahora utilizando el puntero:  indice del 43°= %d\n",(int) shmPtr[43].index);//perfecto

/*
	int u;
	for(u=0;u<100;u++){
		printf("valor del indice para el elemento %d: %d\n",u, shmPtr[u].index);
	}
*/

	//VARS
	//TABLES
	//ETC...



//------------FIN ZONA DE DEFINICION DE ESTRUCTURAS DE DATOS DEL SABUESO------------------







//------------INICIA DEFINICION DE ELEMENTOS DE IPC, CONCURRENCIA Y EXCLUSION-------------
	/*
		En este punto definire los PIPES, semaforos, etc...
	*/
//------------FIN DEFINICION DE ELEMENTOS DE IPC, CONCURRENCIA Y EXCLUSION----------------







//------------INICIA FORK PARA MONITOR DE ARP EN EL BROADCAST-----------------------------

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
			puts("soy el recolector de mensajes ARP iniciando...\n");
			//COmienza a preparar la captura...
			char* dev;
			char errbuf[PCAP_ERRBUF_SIZE];
			pcap_t* descr;//descriptor de la captura
			//const u_char *packet;
			//struct pcap_pkthdr hdr;
			//struct ether_header *eptr; // Ethernet
			struct bpf_program fp;//aca se guardara el programa compilado de filtrado
			bpf_u_int32 maskp;// mascara de subred
			bpf_u_int32 netp;// direccion de red
			if (argc != 2){
				fprintf(stdout,"Modo de Uso %s \"programa de filtrado\"\n",argv[0]);
				return 0;
			}
			dev = pcap_lookupdev(errbuf); //Buscamos un dispositivo del que comenzar la captura (lee por arg, desaparecera esto...)
			printf("\nEcontro como dispositivo %s\n",dev);
			if (dev == NULL){
				fprintf(stderr," %s\n",errbuf); exit(1);
			}
			else{
				printf("Abriendo %s en modo promiscuo\n",dev);
			}
			
			dev = "wlan0";//LA TRAE POR ARGUMENTO, PERO SE LA HARDCODEO POR AHORA, sino usaria la que detecto justo antes (gralmente eth0)

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
			//ahora tengo que ver como pasarle argumentos a la funcion callback
			

			pcap_loop(descr,-1,(pcap_handler)arpCollector_callback,NULL);//OJO, asegurar esta linea con algun if como los anteriores
	
			_exit(EXIT_SUCCESS);

	}//FIN DEL FORK PARA ARPCOLLECTOR


//---------------FIN FORK PARA MONITOR DE ARP EN EL BROADCAST-----------------------------


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
	for(i=0;i<power;i++){
//		arper(mac2guard,arperIface,arperTarget);//arper crea el frame y lo envia(separar)
		arper("00:21:5c:33:09:a5",arperIface,arperTarget);//arper crea el frame y lo envia(separar)
	sleep(1);
	}
//--------------------fin port stealing-----------------------



	//fin del programa principal
	write(1,"FIN DEL PROGRAMA PRINCIPAL\n",sizeof("FIN DEL PROGRAMA PRINCIPAL\n"));
	return 0;
}
