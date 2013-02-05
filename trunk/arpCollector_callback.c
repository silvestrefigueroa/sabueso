//Icludes del arpCollector.c
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
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
#include <pthread.h>

//include de los semaforos:
#include <semaphore.h>

//include de la estructura de argumentos
#include "arpCollector_callbackArguments.h"

//Include de la estructura arpDialog
#include "arpDialogStruct.h"

//Callback starts here!!
void arpCollector_callback(arpCCArgs args[],const struct pcap_pkthdr* pkthdr,const u_char* packet){
	static int count = 1;

	//creo el paquete de datos:
	char paquete[4096];//ajustar este tamaño!! hay que dimensionarlo!!


	//test de semaforos desde la callback
	/*
	//bloqueo semaforo
        sem_wait((sem_t*) & (args[0].shmPtr[43].semaforo));
        //printf("test: id%d title: %s\n", args[0].id,args[0].title);
        //sleep(5);
        sem_post((sem_t*) & (args[0].shmPtr[43].semaforo));
	*/

//	fflush(stdout);
	
	//si.. muy lindo el contador.. pero me gustaria que:
		//muestre datos de la captura:
	struct ether_header* eptr;
	eptr = (struct ether_header*) packet;//apunta a la cabecera ethernet (casteado a ethernet)
	printf("-------------------------------------------------------------------------------------------------------------------\n");
	printf("Paquete numero: %d\n",count);
	//printf("MAC origen en la TRAMA ETHERNET: %s\n", ether_ntoa(eptr−>ether_shost));
	printf("EthernetSourceMAC:             %s\n", ether_ntoa((const struct ether_addr*) eptr->ether_shost));
	//printf("MAC destino en la TRAMA ETHERNET: %s\n", ether_ntoa(eptr−>ether_dhost));
	printf("EthernetDestinationMAC:        %s\n",ether_ntoa((const struct ether_addr*) eptr->ether_dhost));

	
	//ahora examino datos del payload (en este caso es ARP por el filtro)
	//compruebo que sea ARP
	if(ntohs(eptr->ether_type)!=ETHERTYPE_ARP){
		printf("No viaja ARP sobre esta trama (aunque ya esta filtrada...)\n");
	}
	else{
		//puts("vamos con el ARP\n");	
		struct ether_arp *arpPtr;
		//ahora posiciono el puntero en el primer byte(es decir con un offset de size of ether header)
		arpPtr =(struct ether_arp*)(packet+sizeof(struct ether_header));//o lo que es lo mismo packet+14;
		//ahorita, muestro la info que tiene la estructura esta para ARP:
//		fprintf(stdout,"ARP: IP Origen: %d.%d.%d.%d\n",arpPtr->arp_spa[0],arpPtr->arp_spa[1],arpPtr->arp_spa[2],arpPtr->arp_spa[3]);
		fprintf(stdout,"ARP: IP ORIGEN:  %s\n",inet_ntoa(*(struct in_addr *) arpPtr->arp_spa));
//		fprintf(stdout,"ARP: IP Destino: %d.%d.%d.%d\n",arpPtr->arp_tpa[0],arpPtr->arp_tpa[1],arpPtr->arp_tpa[2],arpPtr->arp_tpa[3]);
		fprintf(stdout,"ARP: IP DESTINO: %s\n",inet_ntoa(*(struct in_addr *) arpPtr->arp_tpa));

		printf("ARP: MAC Origen:               %s\n",ether_ntoa((const struct ether_addr*) arpPtr->arp_sha));
		printf("ARP: MAC Destino:              %s\n",ether_ntoa((const struct ether_addr*) arpPtr->arp_tha));

		//lo envio por el PIPE para que lo procese el manejador de dialogos.
		//MENSAJE: "<ethSrcMac|ethDstMac|arpSrcMac|arpDstMac|arpSrcIp|arpDstIp>"
		//EL tamaño seria el tamaño de toooodo eso mas los pipes mas los piquitos.
		//como va a terminar siendo un string...mmmm seria la cantidad de caracteres...
		//tengo los : de la MAC, los . de las IP.. los pipes.. los piquitos.. OJO!!

		//preparo el pipe para SOLO escritura:
		//cierro lectura ya que desde aca SOLO escribimos
		close(args[0].fdPipe[0]);
		//creo el paquete que voy a inyectar en el PIPE (de momento con strcpy, optimizar luego sin usar strcpy)
		//ISSUE REPORTED TO GCode svn
		//si bien el formato que sigue es distinto a lo que usba para debug, me ahorra dolores de cabeza con
		//el strtok, asi que lo dejare de cualquier modo asi!!
		strcpy(paquete,"|");//<ethSrcMac=");
		strcpy(paquete+strlen(paquete),(char*)ether_ntoa((const struct ether_addr*) eptr->ether_shost));
		strcpy(paquete+strlen(paquete),"|");//ethDstMac=");
		strcpy(paquete+strlen(paquete),(char*)ether_ntoa((const struct ether_addr*) eptr->ether_dhost));
		strcpy(paquete+strlen(paquete),"|");//arpSrcMac=");
		strcpy(paquete+strlen(paquete),(char*)ether_ntoa((const struct ether_addr*) arpPtr->arp_sha));
		strcpy(paquete+strlen(paquete),"|");//arpDstMac=");
		strcpy(paquete+strlen(paquete),(char*)ether_ntoa((const struct ether_addr*) arpPtr->arp_tha));
		strcpy(paquete+strlen(paquete),"|");//arpSrcIp=");
		strcpy(paquete+strlen(paquete),inet_ntoa(*(struct in_addr *) arpPtr->arp_spa));
		strcpy(paquete+strlen(paquete),"|");//arpDstIp=");
		strcpy(paquete+strlen(paquete),inet_ntoa(*(struct in_addr *) arpPtr->arp_tpa));
		//escribo en el pipe...
	//	sem_wait((sem_t*) & (args[0].shmPtr[0].semaforo));//bloquea perfecto

		if(!write((int)args[0].fdPipe[1], paquete, strlen(paquete))){
					perror("write()");
					_exit(EXIT_FAILURE);
		}

		//printf("\nLa funcion CALLBACK ha escrito en el PIPE: %s\n",paquete);
		//puedo continuar con el proximo =) finaliza la tarea de la Callback
		//aumenta el contador de frames
		count++;
	}
}

