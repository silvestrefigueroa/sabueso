//includes del sabueso.c
#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

//MIS PROPIAS CABECERAS
//#include "sabueso.h"
#include "arper.h"
#include "parser.h"


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



//MENSAJES ESTATICOS
#define MSG_START "Comienza aqui el programa principal\n"


//Funcion callback del arpCollector.c, luego sacarla como corresponde...
void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet){
	static int count = 1;
	fprintf(stdout," %d, ",count);
	fflush(stdout);
	count++;
	//si.. muy lindo el contador.. pero me gustaria que:
		//filtre la captura
		//Evalue lo que capturo
		//Avise lo que capturo
		//Lo almacene en la tabla de dialogos =)
}


//Aqui comienza la magia =)
int main(int argc, char *argv[]){
	if(0>=write(1,MSG_START, strlen(MSG_START)))
		return -1;
	//variables de datos del programa principal
	char *mac2guard, *mac2guard_copy;//argumento que evolucionara a array y que representa todos los hosts protegidos
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


	//SHAREDMEM
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
			//obtener descriptor pcap
			 // Open a PCAP packet capture descriptor for the specified interface.
/*
			char pcap_errbuf[PCAP_ERRBUF_SIZE];
			pcap_errbuf[0]='\0';
			pcap_t* pcap=pcap_open_live("wlan0",96,1,0,pcap_errbuf);
			if (pcap_errbuf[0]!='\0') {
				fprintf(stderr,"%s\n",pcap_errbuf);
			}
			if (!pcap) {
				exit(1);
			}
*/
			//COmienza a preparar la captura...
			char* dev;
			char errbuf[PCAP_ERRBUF_SIZE];
			pcap_t* descr;//descriptor de la captura
			const u_char *packet;
			struct pcap_pkthdr hdr;
			struct ether_header *eptr; // Ethernet
			bpf_u_int32 maskp;// mascara de subred
			bpf_u_int32 netp;// direccion de red
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
			dev = "wlan0";
			pcap_lookupnet(dev,&netp,&maskp,errbuf); //extraemos la direccion de red y la mascara
			//comenzar captura y obtener descriptor llamado "descr" del tipo pcatp_t*
			//descr = pcap_open_live(dev,BUFSIZ,1,−1,errbuf); //comenzamos la captura en modo promiscuo
			descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf); //comenzar captura en modo promiscuo


			if (descr == NULL){
				printf("pcap_open_live(): %s\n",errbuf);
				exit(1);
			}
//			pcap_loop(descr,−1,my_callback,NULL); //entramos en el bucle (infinito)
			pcap_loop(descr,-1,my_callback,NULL);//entra en el bucle infinito




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
