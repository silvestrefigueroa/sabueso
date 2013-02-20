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


	//bufers para las reentrante de ether e inet
	char ethSrcMacBuf[20];
	char ethDstMacBuf[20];
	char arpSrcMacBuf[20];
	char arpDstMacBuf[20];
	char arpSrcIpBuf[20];
	char arpDstIpBuf[20];
	
	//los punteritos comodos ajaja
	char* ethSrcMac=NULL;
	char* ethDstMac=NULL;
	char* arpSrcMac=NULL;
	char* arpDstMac=NULL;
	char* arpSrcIp=NULL;
	char* arpDstIp=NULL;



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
	printf("EthernetSourceMAC:             %s\n",ether_ntoa((const struct ether_addr*) eptr->ether_shost));
	//printf("MAC destino en la TRAMA ETHERNET: %s\n", ether_ntoa(eptr−>ether_dhost));
	printf("EthernetDestinationMAC:        %s\n",ether_ntoa((const struct ether_addr*) eptr->ether_dhost));

	//utiliznado las funciones reentrantes:
	ethSrcMac=ether_ntoa_r( ((const struct ether_addr*) eptr->ether_shost), ethSrcMacBuf);
	ethDstMac=ether_ntoa_r( ((const struct ether_addr*) eptr->ether_dhost), ethDstMacBuf);

	//ahora examino datos del payload de la trama ethernet (en este caso es ARP si o si por el filtro del arpCollector)
	//compruebo que sea ARP
	if(ntohs(eptr->ether_type)!=ETHERTYPE_ARP){
		printf("No viaja ARP sobre esta trama (aunque ya esta filtrada...)\n");
	}
	else{
		struct ether_arp *arpPtr;
		//ahora posiciono el puntero en el primer byte(es decir con un offset de size of ether header)
		arpPtr =(struct ether_arp*)(packet+sizeof(struct ether_header));//o lo que es lo mismo packet+14;
		//ahorita, muestro la info que tiene la estructura esta para ARP:
//		fprintf(stdout,"ARP: IP Origen: %d.%d.%d.%d\n",arpPtr->arp_spa[0],arpPtr->arp_spa[1],arpPtr->arp_spa[2],arpPtr->arp_spa[3]);
		fprintf(stdout,"ARP: IP ORIGEN:  %s\n",inet_ntoa(*(struct in_addr *) arpPtr->arp_spa));
//		fprintf(stdout,"ARP: IP Destino: %d.%d.%d.%d\n",arpPtr->arp_tpa[0],arpPtr->arp_tpa[1],arpPtr->arp_tpa[2],arpPtr->arp_tpa[3]);
		fprintf(stdout,"ARP: IP DESTINO: %s\n",inet_ntoa(*(struct in_addr *) arpPtr->arp_tpa));

		//ahora utilizo las reentrantes:(los puse casteados a char* porque el compilador chillaba porq tenia const char*!!!!
		arpSrcIp=(char *)inet_ntop(AF_INET,arpPtr->arp_spa, arpSrcIpBuf, sizeof arpSrcIpBuf );
		arpDstIp=(char *)inet_ntop(AF_INET,arpPtr->arp_tpa, arpDstIpBuf, sizeof arpDstIpBuf );

	
		printf("ARP: MAC Origen:               %s\n",ether_ntoa((const struct ether_addr*) arpPtr->arp_sha));
		printf("ARP: MAC Destino:              %s\n",ether_ntoa((const struct ether_addr*) arpPtr->arp_tha));

		//utilizando las reentrantes:		
		arpSrcMac=ether_ntoa_r( ((const struct ether_addr*) arpPtr->arp_sha), arpSrcMacBuf);
		arpDstMac=ether_ntoa_r( ((const struct ether_addr*) arpPtr->arp_tha), arpDstMacBuf);

		printf("hasta ahora tengo: \n %s\n %s\n %s\n %s\n %s\n %s\n",ethSrcMac,ethDstMac,arpSrcMac,arpDstMac,arpSrcIp,arpDstIp);

		//los printf anteriores muestran los datos directamente desde la estructura
		//en adelante los referire mediante macro predefinidas: ETHSRCMAC,ETHDSTMAC,ARPSRCMAC,ARPDSTMAC,ARPSRCIP Y ARPDSTIP

		//preparo el pipe para SOLO escritura:
		//cierro lectura ya que desde aca SOLO escribimos
		close(args[0].fdPipe[0]);

		printf("-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-\n");
//		int srcMacEquals=1;//coinciden por default
//		char* broadcastMac="ff:ff:ff:ff:ff:ff";//Estara mal? deberia inicializar a null y luego cargarle la cadena?deberia reservar?
//		char* zeroMac="0:0:0:0:0:0";//lo mismo que el anterior
//		int doCheckIpI=0;
//		int doCheckSpoofer=0;
	//	int doHitIncrement=0;
//		int nextState=0;//por default, almacenarla y ya
//		char* type=NULL;//consultar posibles valores en tabla_de_dialogos.txt [Arquitectura]
//		int i=0;
//		int dstZeroMacFlag=0;
//		int dstBrdMacFlag=0;

		//mapear los datos para facilitar la manipulacion de los mismos y el codeado.
//		ethSrcMac=ether_ntoa((const struct ether_addr*) eptr->ether_shost);
//		ethDstMac=ether_ntoa((const struct ether_addr*) eptr->ether_dhost);
//		arpSrcMac=ether_ntoa((const struct ether_addr*) arpPtr->arp_sha);
//		arpDstMac=ether_ntoa((const struct ether_addr*) arpPtr->arp_tha);
//		arpSrcIp=inet_ntoa(*(struct in_addr *) arpPtr->arp_spa);
//		arpDstIp=inet_ntoa(*(struct in_addr *) arpPtr->arp_tpa);


		//Ahora como minimo reviso consistencias menores en la trama y el mensaje ARP
//pasted code start here
		if(*ethSrcMac!=*arpSrcMac){
			printf("LOG:se ha detectado inconsistencia entre la MAC origen de la trama y la MAC origen del mensaje ARP\n");//podria ser proxyARP???
			printf("LOG:Son realmente distintos %s y %s  ??\n",ethSrcMac,arpSrcMac);
			//desde ya establezco que la trama es inconsistente en la direccion MAC de origen
//			srcMacEquals=0;//ya que por default coinciden...
		}
		else{//nada... esta ok punto.
			printf("LOG:ethSrcMac=arpSrcMac     OK\n");
		}

		/*
		if(*ethDstMac!=*arpDstMac){
			printf("LOG: POR ENTRAR AQUI SE QUE SON MAC DESTINO DISTINTAS\n");
			//si difieren en la MAC destino pero es el caso particular del broadcast, entonces me aseguro!!
			printf("LOG:entonces %s es distinto de %s\n",ethDstMac,arpDstMac);
			//puts("siguio...\n");
			//printf("LOG:aaaaaaaaaaa tengo: %s y %s \n\n",ethDstMac,"ff:ff:ff:ff:ff:ff");
			if(*ethDstMac==*broadcastMac){
				dstBrdMacFlag=1;
				puts("LOG:ethDsrMac es broadcast!!!\n");
				//mmm iba al broadcast, sera una pregunta realmente? o sera para engañar?
				if(*arpDstMac==*zeroMac){//si es una pregunta ARP, lo marco para consultar su credibilidad? o consulto yo?
					//OK, es ARP request (al menos por la formacion)
					//es al menos una trama aceptable, podria verificarse luego pero al menos la acepto asi!
					//verifico si la IP de destino coincide con la del host que tiene la MAC ethDstMac
					//si quiero realmente probar esto, deberia chequear los pares MACIP de cada host participante
					dstZeroMacFlag=1;
					printf("LOG:puede que sea una pregunta ARP legitima..\n");//faltaria verificar match de ip-mac origen.
					//bien, esta trama esta marcada para verificarse integridad IP, luego steal en busqueda de spoofers
					doCheckIpI=1;
					doCheckSpoofer=1;
					nextState=1;
					type="PASS";
					printf("Finalizada la evaluacion, continua con la carga de datos...\n");
				}
				else{//Si entra aqui, es porque fue al broadcast, pero el ARP tiene un destino FIJO, es muy extraño!!
					printf("LOG:caso extraño, ethDstMac broadcast y arpDstMac Unicast...anomalo!!\n\n");
					//podria verificar el match IP-MAC origen, es un caso para WARN no para evaluarlo porque no viene al caso por ahora.
					//WARNING: deberia comprobarla completamente antes de informar..pero excede los limites del trabajo final
						//He decidido activar el flag type en WARN y no tratar el problema pero si mostrarlo!!
					
				}
			}
			else{//para los casos que no son broadcast en ethernet

				//destino ethernet bien definido, pero MAC destino en ARP DISTINA!!MALFORMACION!!
				//Este curioso caso se da por ejemplo con el DDwrt. el destino en ARP debera ser 0:0:0:0:0:0
				printf("LOG:antes de comparar con zero, tengo %s y %s\n",arpDstMac,zeroMac);
				if(*arpDstMac==*zeroMac){
					dstZeroMacFlag=1;
					//es altamente probable que sea una preguntita del AP que se hace el que no sabe quien es el cliente
					//para confirmar, valido ethSrcMac con arpSrcMac y luego arpSrcMac con arpSrcIp =)
					printf("LOG:Posible mensaje del AP, compruebe que ethSrcMac matchea con arpSrcIp para descartar ataque DoS\n");
					//tratar el error o escapar si OK
					//WARNING, marcar para comprobar y almacenar.
					//Escapa del formato de arpspoofing estudiado, me limito a mostrar el WARN, se descarta la trama
					type="WARN";
					nextState=0;
				}
				//el else de abajo OJO, porque queda el resto en el que las 4 mac son iguales!!
				else{//se trata de MACs destinos AMBIGUOS, es una trama anomala!! a no ser que sea del proxyARP
					printf("LOG:Trama con destino definido, revisando en profundidad....Posible ProxyARP\n\n");
					//No es el caso analizado, se descarta la trama pero se indica el WARN
					type="WARN";
					nextState=0;
					srcMacEquals=2;//por ser un caso anomalo de diferencia..
				}
			}
		}
		else{//macs destino coinciden, o sea bien dirigido..puede ser una trampa, si el origen tiene spoofeada la IP es la trama del atacante
			//o bien son tramas ARP que cayeron en el filtro (y vienen del portstealing) pero spoofeadas tambien por que no?
			//primero que nada chekeo si las MAC origen son iguales (primer verificacion, leo el resultado directamente)
				//si son iguales, veo el match MAC-IP del origen para ver si es ataque (consulto info real)
				switch(srcMacEquals){//lo puse en switch porque podria ser casos especiales de MAC Reservadas, 
							//de momento funciona igual q con IF-else
					case 1:
						//trama OK, debera verificar capa de red IP
							//si no matchea, entonces ALERTO EL ATAQUE!!!
							//SI MATCHEA, tenemos origen OK, destino OK.... nada raro.. me robe un ARP..
							printf("LOG:[Taxonomia de respuesta o ATAQUE], par[%s]-[%s]\n",ethDstMac,arpDstMac);
							//marcar para portstelear y GUARDAR el dialogo en la tabla
							doCheckIpI=1;//siempre primero, es la trivial.si conozco la info real, no noecesito el stealer.
							doCheckSpoofer=1;
							type="PASS";
							nextState=1;
							//Normalmente a no ser que sea una respuesta dirigida al sabueso, no veria estas tramas...
							//es por ello que lo mas seguro es que esta trama sean robadas del porstealing
					break;
					case 0:
							//no son iguales las MAC origen
							//Puede ser proxyARP????(ojo que esta filtrado) o bien 
								//el origen (sender) esta haciendo algo raro
							//WARNING-> inconsistencia en las MAC origen
							printf("LOG:macs origen no coinciden, posible proxyARP o trama anomala\n");
							type="WARN";
							nextState=2;
					break;
					default:
						printf("LOG:caso anomalo no tratado, no pudo determinarse igualdad de mac origen\n");
						//en estos casos, podria meter en la primer evaluacion respecto a las srcMac, numero superiores
						//para casos especiales, de momento no se trata este tipo de "mac reservada"
					break;
				}
		}
		*/






//pasted code finalize here
		//puedo continuar con el proximo =) finaliza la tarea de la Callback
		//aumenta el contador de frames
		count++;
	}
}

