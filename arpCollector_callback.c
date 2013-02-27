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
	count++;//lo hago aca para asegurarme que lo incrmente.. hay muchos breaks dando vueltas
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
		int comparacion=11;//el numero minimo de elementos de una mac segun pcap =) (lo uso en los for..un capricho)
		int savedFlag=0;//se utiliza para saber si se almacenaron o no los datos... en el for de almacenamiento..
		//Ahora como minimo reviso consistencias menores en la trama y el mensaje ARP

		//pasted code start here
//		if(*ethSrcMac!=*arpSrcMac){
		if(strncmp(ethSrcMac,arpSrcMac,strlen(arpSrcMac))){
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
		//antes de hacer el intento de almacenarlo en la tabla, me fijo si fue marcado para dropearlo!! (optimizacion)
		if(dropFlag==1){//drop trama
			printf("LOG: se descarta la trama efectivamente...\n");
			return;
		}
		printf("COMO NO SE DESCARTO LA TRAMA, SIGO EL PROCEDIMIENTO PARA GUARDARLA EN LA TABLA...\n");


//COMIENZA LA PARTE EN LA QUE BUSCA UN LUGAR EN LA TABLA PARA GUARDAR LOS DATOS


		//antes de ir a meterlo en la tabla, deberia comprobar que la informacion que estoy metiendo no existe ya de antes!!!
		//LAZO PARA CHECKEAR SI EXISTE UNA ENTRADA IGUAL O CRUZADA DE ESTE CASO
		for(i=1;i<10;i++){//ese tamaño de la tabla de memoria deberia ser un sizeof o de alguna manera conocerlo ahora hardcodeado

			printf("\nPasada de revision %d\n",i);
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

			if(askFlag==1){
				//si es una pregunta, me fijo si el pregunton esta en la tabla junto a su destino
				printf("-------------------------------------------------mostrar HIT: %d\n", args[0].shmPtr[i].hit);
			}

			//PARA COMPRAR EN LA TABLA TENGO 2 CASOS, O BIEN ES PREGUNTA O BIEN ES RESPUESTA
				//SI ES PREGUNTA ES UNIVOCA
				//SI ES RESPUESTA LA INFORMACION PUEDE SER IDENTICA O ESPECAJA (CRUZADA)

			//COMO SIRVE EL MISMO METODO, SOLO QUE EN LA RESPUESTA PUEDE QUE NECESITE ADEMAS HACERLO CRUZADO, APLICO SIEMPRE
			//EL METODO COMPATIBLE CON LA PREGUNTA ARP Y SOLO EN CASO DE NO SER UNA PREGUNTA APLICO EL CRUZADO =)

//			if(askFlag==1){
				printf("estoy frente a una pregunta ARP\n");
				printf("se va a comparar: %s con %s\n", ethSrcMac, args[0].shmPtr[i].ethSrcMac);
				if(args[0].shmPtr[i].ethSrcMac == NULL){
					printf("\nEntrada de la tabla %d VACIA\n",i);
					continue;//salto para optimizar, sigue comparando con el proximo subindice i
				}
				//no uso else por el continue anterior.. asi que sigo aca else if ethsrcmac==NULL....
				printf("continuo aca no mas...\n");
				printf("la entrada %d no esta vacia..\n",i);
				comparacion=strncmp(args[0].shmPtr[i].ethSrcMac,ethSrcMac,(int) strlen(ethSrcMac));
				printf("valor de la comparacion = %d\n",comparacion);//0 iguales else distintos
				if(comparacion==0){//SI COINCIDIERON
					printf("resulto que eran iguales el de la entrada y este\n");
					if(srcMacEquals==1){//si las mac origen coinciden en la trama actual
						printf("se de antes que las mac origen coinciden en eth y arp\n");
						//comparo la IP origen
						if(!strncmp(args[0].shmPtr[i].arpSrcIp,arpSrcIp,(int) strlen(arpSrcIp))){
							printf("la ip origen arp coincide en la tabla y en este caso\n");
							//comparo el destino de la trama con el de la tabla;
							if(!strncmp(args[0].shmPtr[i].arpDstMac,arpDstMac,(int) strlen(arpDstMac))){
								printf("tenemos la misma mac destino en ARP en tabla y en este caso..\n");
								//misma mac destino, comparo la ip destino y listo
								if(!strncmp(args[0].shmPtr[i].arpDstIp,arpDstIp,(int) strlen(arpDstIp))){
									printf("tambien tenemos la misma IP destino...\n");
									//misma IP destino, si llego aca DESCARTOOO!!!
									printf("LOG: Coincidencia en la tabla, descartar trama\n");
									dropFlag=1;
									break;//rompo el lazo
								}
								else{
									printf("no es la misma IP destino..tenemos inconsistencia de datos!!\n");
									//ip destino distinta, aca ya es inconsistencia.
									//marcar para ver inconsistencia??
									//de momento no descarto
									dropFlag=0;
								}
							}
							else{
								printf("el destino no es el mismo en la tabla y en este caso..\n");
								//el destino ya no es el mismo...continuo...
							}
						}//if args.arpSrcIp == arpSrcIp
						else{
							//no es la misma trama, la ip origen no coincide para el mismo host
							printf("LOG: WARN: IP origen no coincide para el mismo ethSrcMac en esta entrada de la tabla\n");
							//break???log solamente?? meter para hacer un alert???
							//me parece que lo mejor es almacenar y ya..
							//que otro se encargue de tratar las inconsistencias de la tabla
							//QUE NO SEA LA MISMA TRAMA ES SUFICIENTE PARA QUE LA GUARDE!!
						}
					}//if srcMacEquals
					else{//comparo por las dudas que sea caso anomalo ya registrado
						//NO SE GUARDA EN TABLA, SIMPLEMENTE GENERO EL WARNING (PODRIA SER OTRA TABLA?)
						//IGUAL DEBERIA VENIR YA DESCARTADO DESDE LA PRIMER VERIFICACION ESTE CASO...
						printf("LOG: WARNING: caso anomalo llego a compararse en la tabla: mac origen ambigua.. \n");
					}
				}//del if comparacion == 0
				else{//este me vino de 10, porque uso el anterior siempre... pero si NO es pregunta y no llego a conclusion,
					//pruebo tambien el cruzado :)
					printf("la comparacion dio DIFERENTE el actual y la tabla..si no es pregunta, probaria el cruzado\n");
				}
//			}//if de pregunta arp askFlag==1
			if(askFlag==1){//si es una pregunta salteo el cruzado...
				printf("como era una pregunta arp me salteo el cruzado...\n");
				continue;//salto
			}
			printf("sigo aca porque no se trataba de una pregunta..ahora evaluo cruzado...\n");
		//de momento comento la verificacion cruzada.. vamos derecho al almacenamiento
		/*
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
			*/
		}//LAZO FOR


//ACA VA EL CODIGO ENCARGADO DE ALMACENAR LA ENTRADA

		//cancelar si el flag de drop esta arriba
		if(dropFlag!=0){
			printf("LOG: se cancela el almacenamiento de la trama por flag de DROP\n");
			return;//finaliza el tratamiento de esta trama...
		}
		else{
			printf("LOG: se procede al almacenamiento de la trama....\n");
		}
		for(i=0,savedFlag=0;i<10;i++){//lazo para almacenar datos, con flag en "unsaved" por default
			printf("almacenador, pasada %d\n",i);
			//este for recorre todas las entradas de la tabla, si esta "usable" la bloquea, vuelve a verificar, luego almacena y libera"
			if(((int) args[0].shmPtr[i].nextState) == (3)){//si esta disponible (para eliminar o para usar...)
				printf("la entrada %d esta disponible para su uso\n",i);//podria comenzar con las q se de antes que estan en NULL..(optimizar)
				//como esta disponible, pido semaforo
				//bloqueo semaforo
				sem_wait((sem_t*) & (args[0].shmPtr[i].semaforo));
				printf("Bloqueada la entrada %d de la tabla\n", i);
				//compruebo por las dudas de que mientras esperaba el semaforo el anterior "ocupante" haya cambiado la entrada...
				if(args[0].shmPtr[i].nextState == (3)){//para test, inicializar algunas en 3 otras en 4..sola las pasara a 0
					printf("entrada bloqueada y libre para uso!! PERSISTIENDO DATOS...\n");
					args[0].shmPtr[i].ethSrcMac=ethSrcMac;//ESTARA BIEN ESE ALMACENAMIENTO??? O EL PUNTERO QUEDA APUNTANDO ALLI??
					args[0].shmPtr[i].ethDstMac=ethDstMac;
					args[0].shmPtr[i].arpSrcMac=arpSrcMac;
					args[0].shmPtr[i].arpDstMac=arpDstMac;
					args[0].shmPtr[i].arpSrcIp=arpSrcIp;
					args[0].shmPtr[i].arpDstIp=arpDstIp;
					args[0].shmPtr[i].nextState=0;//en principio lo marco como para checkear... de momento hardcodeado
					args[0].shmPtr[i].type=type;
				}
				else{//en caso fallido.. continuar intentando
					//OJO: para cuando se llene puedo hacer que en lugar de un for sea un while y siga y siga hasta flag saved =1..
					printf("LOG: la entrada fue modificada mientras esperaba... continuar con proxima entrada..\n");
					continue;
				}
				//sleep(5);
				printf("liberando semaforo...\n");
				sem_post((sem_t*) & (args[0].shmPtr[i].semaforo));
				savedFlag=1;
			}//IF nextstate 3|4
			if(savedFlag==1){//evaluo el flag que me dice si se guardo la entrada en la tabla..
				printf("se almacenaron los datos en la entrada %d de la tabla\n",i);
				break;
			}
			else{
				printf("los datos no se guardaron en la entrada %d, continuar con la siguiente....\n",i);
				continue;
			}
			//el codigo aqui no hace nada debido al continue del else anterior...
		}//lazo for para almacenar los datos en las entradas
		//verifico que paso al final tras completar el for:
		if(savedFlag==0){//no se guardo en NINGUNA entrada
			printf("LOG: WARNING: la trama no pudo almacenarse en ninguna entrada de la tabla...\n");
		}
		else{
			printf("LOG: se guardo con exito la trama en la tabla\n");
		}
		


		//UNA VEZ TERMINA DE RECORRER... PODRIA USAR ETIQUETAS DEL SIGUIENTE MODO:
			//1| MUSTRO MENSAJE DE TABLA LLENA Y SOLICITO AL MANTENEDOR DE TABLA QUE REVISE LA TABLA O ESPERO...
			//2| VUELVO A LA ETIQUETA DEFINIDA JUSTO ANTES DEL LAZO FOR ;) ASI INTENTO DE NUEVO..
			//3| DEFINIR UN NUMERO DE REINTENTOS.. SI SE LLEGA A ESE NUMERO, ENTONCES BREAKEAR Y MOSTRAR EL ERROR
			//OJO: NO SE SI LOS OTROS FRAMES CAPTURADOS SE VERAN AFECTADOS A LA HORA DE ALMACENAR ESTOS DATOS.. :(
				//QUIZA HASTA ESTA SEA UNA TAREA PARA HILOS :(
				

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
	}
