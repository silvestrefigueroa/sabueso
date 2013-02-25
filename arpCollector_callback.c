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
		int srcMacEquals=1;//coinciden por default
		char* broadcastMac="ff:ff:ff:ff:ff:ff";//Estara mal? deberia inicializar a null y luego cargarle la cadena?deberia reservar?
		char* zeroMac="0:0:0:0:0:0";//lo mismo que el anterior
		int doCheckIpI=0;
		int doCheckSpoofer=0;
		int doCheckWAck=0;
	//	int doHitIncrement=0;
		int nextState=0;//por default, almacenarla y ya
		char* type=NULL;//consultar posibles valores en tabla_de_dialogos.txt [Arquitectura]
		int i=0;
		int dstZeroMacFlag=0;
		int dstBrdMacFlag=0;
		int askFlag=0;
		int dropFlag=0;
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
			printf("LOG:se ha detectado inconsistencia entre la MAC origen de la trama y la MAC origen del mensaje ARP\n");
			//podria haber sido proxyARP???
			printf("LOG:Son realmente distintos %s y %s  ??\n",ethSrcMac,arpSrcMac);
			//desde ya establezco que la trama es inconsistente en la direccion MAC de origen
			srcMacEquals=0;//ya que por default coinciden...
		}
		else{//si en lugar de no coincidir, viene como es esperable...
			printf("LOG:ethSrcMac=arpSrcMac     OK\n");
			srcMacEquals=1;//aunque por default coinciden
		}
		if(*ethSrcMac==*arpSrcMac){
			printf("LOG: LAS MAC ORIGEN SON IGUALES por compracion con == \n");
		}
		if(!strcmp(ethSrcMac,arpSrcMac)){
			printf("LOG las mac origen son iguales por strcmp\n");
		}
		printf("------sigue-----\n");
		if(strcmp(ethDstMac,arpDstMac)){
			printf("LOG: las mac destino son DISTINTAS por strcmp\n");
			//codigo para cuando son distintas aqui...
//			if(*ethDstMac==*broadcastMac){//old bad mode
			if(!strcmp(ethDstMac,broadcastMac)){
				dstBrdMacFlag=1;
				puts("LOG:ethDsrMac es broadcast por strcmp!!!\n");
				//mmm iba al broadcast, sera una pregunta realmente? o sera para engañar?
//				if(*arpDstMac==*zeroMac){//old bad mode
				if(!strcmp(arpDstMac,zeroMac)){//si devuelve 0 son iguales :)
					//si es una pregunta ARP, lo marco para consultar su credibilidad? o consulto yo en db conocimiento?
					//OK, tiene la arquitectura de ARP request/question
					//es al menos una trama aceptable, podria verificarse luego pero al menos la guardo
					//verifico si la IP de destino coincide con la del host que tiene la MAC ethDstMac en dbconocimiento
					//si quiero realmente probar esto, deberia chequear los pares MACIP de cada host participante
					dstZeroMacFlag=1;
					printf("LOG:puede que sea una pregunta ARP legitima..\n");//faltaria verificar match de ip-mac origen.
					//bien, esta trama esta marcada para verificarse integridad IP, luego steal en busqueda de spoofers
					doCheckIpI=1;
					doCheckSpoofer=1;
					nextState=1;
					type="PASS";//deberian ser un macro de variable entero y ya..
					askFlag=1;//porque supongo es pregunta ARP
					printf("Finalizada la evaluacion, continua con la carga de datos...\n");
				}
				else{//Si entra aqui, es porque fue al broadcast, pero el ARP tiene un destino FIJO, es muy extraño!!
					printf("LOG:caso extraño, ethDstMac broadcast y arpDstMac Unicast...anomalo!!\n\n");
					//podria verificar el match IP-MAC origen, es un caso para WARN no para evaluarlo 
					//He decidido activar el flag type en WARN y no tratar el problema pero si mostrarlo!!
					type="WARN";//deberian ser un macro de variable entero y ya..
					
				}
			}
			else{
				printf("no estaba dirigido al broadcast ethernet, es UNICAST :p\n");
				//bueno aqui va el codigo para cuando estaba la trama dirigida a una mac especifica:
				//destino ethernet bien definido, pero MAC destino en ARP DISTINA!!MALFORMACION!!
				//Este curioso caso se da por ejemplo con el DDwrt. el destino en ARP debera ser 0:0:0:0:0:0
				printf("LOG:antes de comparar con zero, tengo %s y %s\n",arpDstMac,zeroMac);
//				if(*arpDstMac==*zeroMac){//bad old style
				if(!strcmp(arpDstMac,zeroMac)){
					printf("LOG: por strcmp, mac destino en ARP es todo 0:  %s\n",arpDstMac);
					dstZeroMacFlag=1;
					//es altamente probable que sea una preguntita del AP que se hace el que no sabe quien es el cliente
					//para confirmar, valido ethSrcMac con arpSrcMac y luego arpSrcMac con arpSrcIp =)
					printf("LOG:Posible mensaje del AP,compruebe que ethSrcMac matchea con arpSrcIp para descartar DoS\n");
					//tratar el error o escapar si OK
					//WARNING, marcar para comprobar y almacenar.
					//Escapa del formato de arpspoofing estudiado, me limito a mostrar el WARN, se descarta la trama
					type="WARN";
					nextState=0;
					dropFlag=1;//descarto los del AP
				}
				//el else de abajo OJO, porque queda el resto en el que las 4 mac son iguales!!
				else{//se trata de MACs destinos AMBIGUOS, es una trama anomala!! a no ser que sea del proxyARP
					printf("LOG:por strcmp, Trama con destino definido, revisando en profundidad....Posible ProxyARP\n\n");
					//No es el caso analizado, se descarta la trama pero se indica el WARN
					type="WARN";
					nextState=0;
					srcMacEquals=2;//por ser un caso anomalo de diferencia..
				}
			}
		}
		else{
			printf("LOG: mac destino IGUALES por strcmp, sera el caso de un mensaje respuesta ARP??\n");
			//aqui el codigo para cuando las mac destino son IGUALES:
			//macs destino coinciden, o sea bien dirigido
			//puede ser una trampa, si el origen tiene spoofeada la IP es la trama del atacante
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
			}//case
		}//else en el que son IGUALES las mac destino (viene del if de si son distintas)



//COMIENZA LA PARTE EN LA QUE BUSCA UN LUGAR EN LA TABLA PARA GUARDAR LOS DATOS


		//antes de ir a meterlo en la tabla, deberia comprobar que la informacion que estoy metiendo no existe ya de antes!!!
		for(i=1;i<100;i++){//ese tamaño de la tabla de memoria deberia ser un sizeof o de alguna manera conocerlo ahora hardcodeado

			printf("Revisor de tabla, pasada %d\n",i);
			

			//OJO: PODRIA OPTIMIZARSE EN FUNCION DEL VALOR DEL NEXTSTATE DE LA ENTRADA QUE SE ESTA COMPARANDO


			//debera comparar con todas entradas en la tabla, si coinciden TENGO UN CONOCIMIENTO, si es igual DESCARTAR

			//comprobar si existe la entrada en la tabla (de cualquier sentido) (IDA O VUELTA)
			
			//pero si la entrada en la tabla esta para descartar o para usar entonces saltar el CICLO ACTUAL
			/*
			if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).hit==(3|4)){
				//saltar ciclo
				printf("saltando esta entrada de la tabla por no ser conocimiento...\n");
				continue;
			}
			*/
			int comparacion=11;//el numero minimo de elementos de una mac segun pcap =)
			if(askFlag==1){
				//si es una pregunta, me fijo si el pregunton esta en la tabla junto a su destino
				printf("-------------------------------------------------mostrar HIT: %d\n", args[0].shmPtr[i].hit);
			}
			//test de semaforos desde la callback
		        /*
	        	//bloqueo semaforo
		        sem_wait((sem_t*) & (args[0].shmPtr[43].semaforo));
			//printf("test: id%d title: %s\n", args[0].id,args[0].title);
			//sleep(5);
		        sem_post((sem_t*) & (args[0].shmPtr[43].semaforo));
		        */



			//PARA COMPRAR EN LA TABLA TENGO 2 CASOS, O BIEN ES PREGUNTA O BIEN ES RESPUESTA
				//SI ES PREGUNTA ES UNIVOCA
				//SI ES RESPUESTA LA INFORMACION PUEDE SER IDENTICA O ESPECAJA (CRUZADA)

			//PRIMERO VERIFICARE PARA EL CASO DE PREGUNTA ARP, LUEGO PARA RESPUESTA

			if(askFlag==1){
				printf("estoy frente a una pregunta ARP\n");
				printf("se va a comparar: %s con %s\n", ethSrcMac, args[0].shmPtr[i].ethSrcMac);
				if(args[0].shmPtr[i].ethSrcMac != NULL){
					printf("la entrada %d no esta vacia..\n",i);
					comparacion=strncmp(args[0].shmPtr[i].ethSrcMac,ethSrcMac,(int) strlen(ethSrcMac));
					printf("valor de la comparacion = %d\n",comparacion);//0 iguales else distintos
					printf("resulto que eran iguales el de la entrada y este\n");
					if(comparacion==0){//SI COINCIDIERON
						if(srcMacEquals==1){//si las mac origen coinciden en la trama actual
							//comparo la IP origen
							if(!strncmp(args[0].shmPtr[i].arpSrcIp,arpSrcIp,(int) strlen(arpSrcIp))){
								//comparo el destino de la trama con el de la tabla;
								if(!strncmp(args[0].shmPtr[i].arpDstMac,arpDstMac,(int) strlen(arpDstMac))){
									//misma mac destino, comparo la ip destino y listo
									if(!strncmp(args[0].shmPtr[i].arpDstIp,arpDstIp,(int) strlen(arpDstIp))){
										//misma IP destino, si llego aca DESCARTOOO!!!
										printf("LOG: Coincidencia en la tabla, descartar trama\n");
										dropFlag=1;
										break;//rompo el lazo
									}
									else{
										//ip destino distinta, aca ya es inconsistencia.
										//marcar para ver inconsistencia??
										//de momento no descarto
										dropFlag=0;
									}
								}
								else{
									//el destino ya no es el mismo...continuo...
								}
							}//if args.arpSrcIp == arpSrcIp
							else{
								//no es la misma trama, la ip origen no coincide para el mismo host
								printf("LOG: IP origen no coincide para el mismo host en esta entrada de la tabla\n");
								//break???log solamente?? meter para hacer un alert???
								//me parece que lo mejor es almacenar y ya..
								//que otro se encargue de tratar las inconsistencias de la tabla
								//QUE NO SEA LA MISMA TRAMA ES SUFICIENTE PARA QUE LA GUARDE!!
							}
						}//if srcMacEquals
						else{//comparo por las dudas que sea caso anomalo ya registrado
							//NO SE GUARDA EN TABLA, SIMPLEMENTE GENERO EL WARNING (PODRIA SER OTRA TABLA?)
							//IGUAL DEBERIA VENIR YA DESCARTADO DESDE LA PRIMER VERIFICACION ESTE CASO...
							printf("LOG: WARNING: caso anomalo llego a compararse en la tabla.. \n");
						}
					}//del if comparacion == 0
				}//if null
			}//if de pregunta arp askFlag==1
			else{//si no es una pregunta... podra ser que sea completa o una respuesta...
				printf("Esto no es pregunta ARP, asi que hago checkeo completo...\n");
				printf("la entrada cruzada %d no esta vacia..\n",i);
				if(args[0].shmPtr[i].ethSrcMac != NULL){
					comparacion=strncmp(args[0].shmPtr[i].ethSrcMac,ethDstMac,(int) strlen(ethDstMac));
					printf("valor de la comparacion cruzada = %d\n",comparacion);//0 iguales else distintos
					printf("resulto que eran iguales el de la entrada cruzada y este\n");
					if(comparacion==0){//SI COINCIDIERON CRUZADAS
						//comparo la IP origen
						if(!strncmp(args[0].shmPtr[i].arpSrcIp,arpDstIp,(int) strlen(arpDstIp))){
							//comparo el destino de la trama con el origen de la tabla;
							if(!strncmp(args[0].shmPtr[i].arpDstMac,arpSrcMac,(int) strlen(arpSrcMac))){
								//coinciden las mac cruzadas, comparar IPs
								if(!strncmp(args[0].shmPtr[i].arpDstIp,arpSrcIp,(int) strlen(arpSrcIp))){
									//misma IP destino, si llego aca DESCARTOOO!!!
									printf("LOG: Coincidencia en la tabla cruzada  descartar trama\n");
									dropFlag=1;
									break;//rompo el lazo
								}
								else{//ojo que estamos en la cruzada
									//ip INCONSISTENTE y distinta, aca ya es inconsistencia.(y distinto obvio)
									//marcar para ver inconsistencia??
									//de momento no descarto por ser DISTINTAS en algo
									dropFlag=0;
								}
							}//if arpDstMac==arpSrcMac
							else{
								//La entrada no contiene al valor actual
								//coincidio cruzado UN SOLO HOST
								//problema de inconsistencia tambein
								printf("LOG: no hubo coincidencias completa, es un caso de inconsistencia!!\n");
							}
						}//if args.arpSrcIp==arpDstIp
						else{	
							//no es la misma trama, la ip origen no coincide para el mismo host
							printf("LOG: Inconsistencia IP aqui tambien!!!\n");
							//break???log solamente?? meter para hacer un alert???
							//me parece que lo mejor es almacenar y ya..
							//que otro se encargue de tratar inconsistencias de la tabla
							//QUE NO SEA LA MISMA TRAMA ES SUFICIENTE PARA QUE LA GUARDE!!
						}
					}//if de si comparacion == 0 (CRUZADAS)
					else{//comparo por las dudas que sea caso anomalo ya registrado
						//nada.. significa que no hubo coincidencia y sigo mirando..
						printf("LOG: NO HUBO CONSISTENCIA EN ESTA PASADA...\n");
					}
				}//Si no es NULL la entrada...(solo para potimizar)
			}//else de si no es una pregunta

/*

				printf("se va a comparar : %s con %s\n",( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).ethSrcMac ),ethSrcMac );
				if(  ((((arpDTMWorker_arguments *) arguments)->shmPtr[i]).ethSrcMac) != NULL){
					printf("no nulo\n");
					comparacion=strncmp( ((((arpDTMWorker_arguments *) arguments)->shmPtr[i]).ethSrcMac), ethSrcMac, (int) strlen(ethSrcMac));
					printf("valor de la comparacion = %d\n",comparacion);
					if(comparacion == 0){
						printf("eran iguales entonces por el strlen\n");
					}
					else{
						printf("eran DISTINTOS por el strlen\n");
					}
				}
				else{
					//si esta nula la entrada, saltarla y ahorrar tiempo!!
					continue;//salta con este?
					printf("era nulo....\n");
				}
				if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).ethSrcMac==ethSrcMac){
					printf("este pregunton ya pregunto antes, a ver si es el mismo destino...\n");
					if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).arpDstIp==arpDstIp){
						printf("es el mismo destino, a ver si no esta spoofeada la pregunta...\n");
						//ahora puedo hacer una busqueda en la tabla..si coincide que la ip es distinta entonces
						//se que estamos frente a una pregunta spoofeada
						if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).arpSrcIp==arpSrcIp){
							//si entra aca significa que coincidio origen, destino y las IP origen
							printf("esta entrada ya existia en la tabla, la descartamos...\n");
							dropFlag=1;//descartar...
							//incremento el hit de la entrada.
							//bloquear entrada...
							sem_wait( & ((((arpDTMWorker_arguments *) arguments)->shmPtr[i]).semaforo) );
							//usar la entrada de la tabla
							//Si estaba para eliminar, le cambio el nextState
							if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).nextState==(3||4)){
								printf("Esta entrada se iba a eliminar...\n");
								(((arpDTMWorker_arguments *) arguments)->shmPtr[i]).nextState=1;
							}
							//aumento el hit
							(((arpDTMWorker_arguments *) arguments)->shmPtr[i]).hit++;
							//liberar entrada de la tabla
							sem_post( & ((((arpDTMWorker_arguments *) arguments)->shmPtr[i]).semaforo) );
							//ahora corto porque solo queria aumentar el HIT
							break;
						}
						else{
							printf("se encontro la entrada, pero difieren IP origen, posible pregunta spoofed\n");
							dropFlag=0;//corresponde.... por mas que venga de antes en 0
							doCheckSpoofer=1;//sip.. si hay inconsistencia hay algo raro..
						}
					}
				}
			}
















			//printf("Estado de la entrada n°%d: %d\n", i,(((arpDTMWorker_arguments *) arguments)->shmPtr[i]).hit  );
			//Comparo las ethSrcMac de la tabla con las MAC que tengo en este hilo
			printf("mostrando comparacion: %s con %s \n",(((arpDTMWorker_arguments *) arguments)->shmPtr[i]).ethSrcMac,ethSrcMac);
			if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).ethSrcMac==ethSrcMac){
				printf("Coincidencia de ethSrcMac_en_tabla con ethSrcMac\n");
				//comprobar si el otro participande del dialogo es el de ahora:
				if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).ethDstMac==ethDstMac){
					printf("coinsidencia de dialogo!! tambien coincidieron las mac destino\n");
					//comprobar integridad IP:
					if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).arpSrcIp==arpSrcIp){
						printf("IP src OK\n");
						if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).arpDstIp==arpDstIp){
							printf("IP destino OK, entrada REPETIDA EN LA TABLA\n");
							dropFlag=1;
						}
						else{
							printf("conflicto: La IP destino actual no coincide con la almacenada posible spoofing\n");
							//marcar de algun modo el conflicto!!! (podria ser el hit???)
							dropFlag=0;
						}
					}
					else{
						//IP origen de ahora no coincide con el origen de la entrada almacenada
						printf("IP origen en discordia con la entrada almacenada\n");
						//deberia marcarla para revisar, entonces se almacena
						dropFlag=0;
					}
				}
				else{
					//no seria la misma trama porque tienen mismo origen pero distinto destino en MAC
					dropFlag=0;
				}
			}
			else{
				if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).ethSrcMac==ethDstMac){
					printf("Coincidencia de ethDstMac_en_tabla con ethSrcMac\n");
					//comprobar si el otro participande del dialogo es el de ahora:
					if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).ethDstMac==ethSrcMac){
						printf("coinsidencia de dialogo pero cruzado!!\n");
						//comprobar integridad IP:
						if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).arpSrcIp==arpDstIp){
							//macs iguales aunque cruzadas:

							printf("IP src y dst cruzadas OK\n");
							if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).arpDstIp==arpSrcIp){
								printf("IP destino OK, entrada REPETIDA EN LA TABLA (CRUZADA)\n");
								dropFlag=1;
							}
							else{
								printf("conflicto: IP dest. actual no coincide con la almacenada posible spoofing\n");
								//marcar de algun modo el conflicto!!! (podria ser el hit???)
								dropFlag=0;
							}
						}
						else{
							//IP origen de ahora no coincide con el origen de la entrada almacenada
							printf("IP origen (CRUZADA) en discordia con la entrada almacenada\n");
							//deberia marcarla para revisar, entonces se almacena
							dropFlag=0;
						}
					}
					else{
						//no seria la misma trama porque tienen mismo origen pero distinto destino en MAC
						dropFlag=0;
					}
				}
			}//else if
			//ahora si esta dropFlag arriba, entonces corto el lazo y termino descartando la trama
			if(dropFlag==1){
				printf("LOG: se desacarta la trama (quiza por coincidir en la tabla)\n");
				return 0;
			}		
		}//lazo FOR
		//facil, si esta activo el DROP, pues finalizar, sino continuar ejecucion
		if(dropFlag==1){
			printf("LOG: se desacarta la trama (quizaa por coincidir en la tabla)\n");
			return 0;
		}




*/



//FINALIZA LA BUSQUEDA DE LUGAR EN LA TABLA

		//puedo continuar con el proximo =) finaliza la tarea de la Callback
		//aumenta el contador de frames
	}
count++;
}
	}
