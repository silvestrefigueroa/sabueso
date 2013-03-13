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

#define TABLE_SIZE args[0].tableSize//TAMAÑO DE LA TABLA DE DIALOGOS
#define ARPASKERS_TABLE_SIZE args[0].arpAskers_tableSize//TAMAÑO DE LA TABLA DE ASKERS


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

//		printf("hasta ahora tengo: \n %s\n %s\n %s\n %s\n %s\n %s\n",ethSrcMac,ethDstMac,arpSrcMac,arpDstMac,arpSrcIp,arpDstIp);

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
	//	int dstZeroMacFlag=0;
	//	int dstBrdMacFlag=0;
		int askFlag=0;
		int dropFlag=0;
		int comparacion=11;//el numero minimo de elementos de una mac segun pcap =) (lo uso en los for..un capricho)
		int savedFlag=0;//se utiliza para saber si se almacenaron o no los datos... en el for de almacenamiento..
		int writableFlag=0;
		//Ahora como minimo reviso consistencias menores en la trama y el mensaje ARP
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
			if(!strcmp(ethDstMac,broadcastMac)){
//				dstBrdMacFlag=1;
				puts("LOG:ethDsrMac es broadcast por strcmp!!!\n");
				//mmm iba al broadcast, sera una pregunta realmente? o sera para engañar?
				if(!strcmp(arpDstMac,zeroMac)){//si devuelve 0 son iguales :)
					//si es una pregunta ARP, lo marco para consultar su credibilidad? o consulto yo en db conocimiento?
					//OK, tiene la arquitectura de ARP request/question
					//es al menos una trama aceptable, podria verificarse luego pero al menos la guardo
					//verifico si la IP de destino coincide con la del host que tiene la MAC ethDstMac en dbconocimiento
					//si quiero realmente probar esto, deberia chequear los pares MACIP de cada host participante
//					dstZeroMacFlag=1;
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
				if(!strcmp(arpDstMac,zeroMac)){
					printf("LOG: por strcmp, mac destino en ARP es todo 0:  %s\n",arpDstMac);
//					dstZeroMacFlag=1;
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
		printf("COMO NO SE DESCARTO LA TRAMA, SIGO EL PROCEDIMIENTO PARA REVISAR Y LUEGO GUARDARLA EN LA TABLA...\n");


//COMIENZA LA PARTE EN LA QUE BUSCA UN LUGAR EN LA TABLA PARA GUARDAR LOS DATOS


		//antes de ir a meterlo en la tabla, deberia comprobar que la informacion que estoy metiendo no existe ya de antes!!!
		//LAZO PARA CHECKEAR SI EXISTE UNA ENTRADA IGUAL O CRUZADA DE ESTE CASO
		for(i=0;i<TABLE_SIZE;i++){//ese tamaño de la tabla de memoria deberia ser un sizeof o de alguna manera conocerlo ahora hardcodeado

			printf("\nPasada de revision %d\n",i);
			//debera comparar con todas entradas en la tabla, si coinciden TENGO UN CONOCIMIENTO, si es igual DESCARTAR
			//comprobar si existe la entrada en la tabla (de cualquier sentido) (IDA O VUELTA)
			if(askFlag==1){
				//si es una pregunta, me fijo si el pregunton esta en la tabla junto a su destino
				printf("-------------------------------------------------mostrar HIT: %d\n", args[0].shmPtr[i].hit);
			}

			//PARA COMPRAR EN LA TABLA TENGO 2 CASOS, O BIEN ES PREGUNTA O BIEN ES RESPUESTA
				//SI ES PREGUNTA ES UNIVOCA
				//SI ES RESPUESTA LA INFORMACION PUEDE SER IDENTICA O ESPECAJA (CRUZADA)

			//COMO SIRVE EL MISMO METODO, SOLO QUE EN LA RESPUESTA PUEDE QUE NECESITE ADEMAS HACERLO CRUZADO, APLICO SIEMPRE
			//EL METODO COMPATIBLE CON LA PREGUNTA ARP Y SOLO EN CASO DE NO SER UNA PREGUNTA APLICO EL CRUZADO =)

printf("hasta ahora tengo: \n %s\n %s\n %s\n %s\n %s\n %s\n",ethSrcMac,ethDstMac,arpSrcMac,arpDstMac,arpSrcIp,arpDstIp);

			printf("estoy frente a una pregunta o respuesta ARP\n");
			printf("se va a comparar: %s con %s\n", ethSrcMac, (char*)args[0].shmPtr[i].ethSrcMac);
			if(args[0].shmPtr[i].ethSrcMac == NULL){
				printf("\nEntrada de la tabla %d VACIA\n",i);
				printf("______________________________________________________________\n");
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
								printf("no es la misma IP destino. Inconsistencia de datos!!\n");
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
						printf("LOG: WARN INCONS.: srcIP no coincide para el mismo ethSrcMac en la tabla\n");
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
			if(askFlag==1){//si es una pregunta salteo el cruzado...
				printf("como era una pregunta arp me salteo el cruzado...\n");
				continue;//salto
			}
			printf("sigo aca porque no se trataba de una pregunta..ahora evaluo cruzado...\n");
			//REVISION CRUZADA
			//EN ESTA REVISION LO QUE HAGO ES REVISAR AL REVES LAS ENTRADAS, ES DECIR, HAGO DE CUENTA QUE EL EMISOR ES EL RECEPTOR Y COMPARO
			//ESTO LO HAGO PARA EVITAR DUPLICIDAD YA QUE LO UNICO QUE ME INTERESA ES LAS DUPLAS MAC-IP NO IMPORTA SI ES EMISOR O RECEPTOR

			printf("estoy frente a una respuesta ARP CRUZADA\n");
			printf("se va a comparar: %s con %s\n", ethSrcMac, (char*)args[0].shmPtr[i].ethDstMac);//a ver si el actual emisor fue ante receptor..y asi cruzada..
			if(args[0].shmPtr[i].ethSrcMac == NULL){
				printf("\nEntrada cruzada de la tabla %d VACIA\n",i);
				printf("______________________________________________________________\n");
				continue;//salto para optimizar, sigue comparando con el proximo subindice i
			}
			//no uso else por el continue anterior.. asi que sigo aca else if ethsrcmac==NULL....
			printf("continuo cruzado aca no mas...\n");
			printf("la entrada %d no esta vacia..\n",i);
			comparacion=strncmp(args[0].shmPtr[i].ethDstMac,ethSrcMac,(int) strlen(ethSrcMac));
			printf("valor de la comparacion cruzada = %d\n",comparacion);//0 iguales else distintos
			if(comparacion==0){//SI COINCIDIERON
				printf("resulto que eran iguales pero cruzados el de la entrada y este\n");
/*puedo evitar anidamiento aqui*/	if(srcMacEquals==1){//si las mac origen coinciden en la trama actual
					printf("se de antes que las mac origen coinciden en eth y arp\n");
					//comparo la IP origen cruzada con la destino de la tabla
					if(!strncmp(args[0].shmPtr[i].arpDstIp,arpSrcIp,(int) strlen(arpSrcIp))){
						printf("la ip origen arp cruzada coincide en la tabla y en este caso\n");
						//comparo el destino de la trama con el ORIGEN de la tabla porque esta cruzada
						if(!strncmp(args[0].shmPtr[i].arpSrcMac,arpDstMac,(int) strlen(arpDstMac))){
							printf("tenemos la misma mac ORIGEN en ARP en tabla y en este caso..\n");
							//misma mac ORIGEN, comparo la ip ORIGEN en tabla con el destino de este caso y listo
							if(!strncmp(args[0].shmPtr[i].arpSrcIp,arpDstIp,(int) strlen(arpDstIp))){
								printf("tambien tenemos la misma IP origen cruzado...\n");
								//misma IP origen en la tabla coincide con el destino de este caso.llego aca DESCARTOOO!!!
								printf("LOG: Coincidencia CRUZADA en la tabla, descartar trama\n");
								dropFlag=1;
								break;//rompo el lazo
							}
							else{
								printf("no es la misma IP origen en tabla y destino en este caso. Inconsistencia de datos!!\n");
								//Para comprender este caso, revisar comentarios en la revision derecha (esta es la cruzada)
								dropFlag=0;
							}
						}
						else{
							printf("el ORIGEN en la tabla no coincidio con el destino de este caso cruzado..\n");
							//el ORIGEN no es el destino (cruzados) asi que continuo...
						}
					}//if args.arpDstIp == arpSrcIp
					else{
						//no es la misma trama, la ip origen no coincide para el mismo host
						printf("LOG: WARN INCONSISTENCIA CRUZADA.: DUPLAS IP MAC NO COINCIDEN PARA LA MISMA MAC EN TABLA VS ESTE CASO (ESTA TRAMA)\n");
						//PARA COMENTARIOS AL RESPECTO REVISAR SIEMPRE LA REVISION DERECHA (ANTERIOR) Y NO LA CRUZADA (ESTA)
					}
				}//if srcMacEquals. PUEDO ELIMINAR ANIDAMIENTO CON UN SIMPLE FLAG PARA CONTINUAR O SALTAR =)
				else{//comparo por las dudas que sea caso anomalo ya registrado
					printf("LOG: WARNING en algoritmo cruzado: caso anomalo llego a compararse en la tabla: mac origen ambigua.. \n");
				}
			}//del if comparacion == 0
			else{//este me vino de 10, porque uso el anterior siempre... pero si NO es pregunta y no llego a conclusion,
				//pruebo tambien el cruzado :)
				printf("la comparacion CRUZADA dio DIFERENTE entre el caso actual y la entrada de la tabla..continuo con la sgte entrada\n");
			}
		}//LAZO FOR

//ACA VA EL CODIGO ENCARGADO DE ALMACENAR LA ENTRADA

		//cancelar si el flag de drop esta arriba (es decir, si se decidio antes dropear la trama)
		if(dropFlag!=0){
			printf("LOG: se cancela el almacenamiento de la trama por flag de DROP\n");
			return;//finaliza el tratamiento de esta trama...
		}
		else{
			printf("LOG: se procede al almacenamiento de la trama....\n");
		}
		for(i=0,savedFlag=0;i<TABLE_SIZE;i++){//lazo para almacenar datos, con flag en "unsaved" por default
			printf("___________________________________________________________________________\n");
			printf("almacenador, pasada %d\n",i);

			//dentro de este for se recorre todas las entradas de la tabla,
			// si esta "usable" la bloquea, vuelve a verificar, luego almacena y libera"
			//si esta disponible (para eliminar o para usar...)
			//if( 3 <= (((int) args[0].shmPtr[i].nextState <= 4)) ){
			
			//como no me anduvo ni la doble condicion ni el or con los || hago un switch y manejo un flag
			switch(((int) args[0].shmPtr[i].nextState)){
				case 3:
					writableFlag=1;
				break;
				case 4:
					writableFlag=1;
				break;

				default:
					printf("caso default:, no se puede usar la entrada porque su netxtState no es apropiado\n");
				break;
			}
			if(writableFlag==1){

				printf("la entrada %d esta disponible para su uso\n",i);
				//podria haber comenzado con las q se de antes que estan en NULL..(optimizar)

				//INICIA ZONA CRITICA, PIDO EL SEMAFORO
				sem_wait((sem_t*) & (args[0].shmPtr[i].semaforo));
				printf("Bloqueada la entrada %d de la tabla\n", i);
				//compruebo por las dudas de que mientras esperaba el semaforo el anterior "ocupante" haya cambiado la entrada
				writableFlag=0;
				switch(((int) args[0].shmPtr[i].nextState)){
					case 3:
						writableFlag=1;
					break;
					case 4:
						writableFlag=1;
					break;
					default:
						printf("caso default, no se puede usar la entrada\n");
					break;
				}
				if(writableFlag==1){
					printf("entrada bloqueada y libre para uso!! PERSISTIENDO DATOS...\n");
					args[0].shmPtr[i].ethSrcMac=(char *)malloc (strlen(ethSrcMac));
					strcpy(args[0].shmPtr[i].ethSrcMac,ethSrcMac);
					args[0].shmPtr[i].ethDstMac=(char *)malloc (strlen(ethDstMac));
					strcpy(args[0].shmPtr[i].ethDstMac,ethDstMac);
					args[0].shmPtr[i].arpSrcMac=(char *)malloc (strlen(arpSrcMac));
					strcpy(args[0].shmPtr[i].arpSrcMac,arpSrcMac);
					args[0].shmPtr[i].arpDstMac=(char *)malloc (strlen(arpDstMac));
					strcpy(args[0].shmPtr[i].arpDstMac,arpDstMac);
					args[0].shmPtr[i].arpDstIp=(char *)malloc (strlen(arpDstIp));
					strcpy(args[0].shmPtr[i].arpDstIp,arpDstIp);
					args[0].shmPtr[i].arpSrcIp=(char *)malloc (strlen(arpSrcIp));
					strcpy(args[0].shmPtr[i].arpSrcIp,arpSrcIp);
					args[0].shmPtr[i].nextState=nextState;//OJO son enteros
					args[0].shmPtr[i].type=(char *)malloc (strlen(type));
					strcpy(args[0].shmPtr[i].type,type);
					printf("ya paso la asignacion por strcpy\n");
					printf("AHORA DEBERIA EVALUAR doCheckWAck=%d doCheckIpI=%d doCheckSpoofer=%d\n",doCheckWAck,doCheckIpI,doCheckSpoofer);

					//Luego.. deberia comprobar si el pregunton existe en la tabla de arpAskers..
						//Si existe tomo el index de esa entrada y lo seteo en el index de esta entrada
						//Si no existe lo inserto y luego tomo el index para guardarlo en ESTA entrada en el campo arpAskerIndex


				}
				else{//en caso fallido.. INFORMAR Y LIBERAR.. LUEGO CONTINUAR
					//OJO: para cuando se llene puedo hacer que en lugar de un for sea un while y siga y siga hasta flag saved =1..
					printf("LOG: la entrada fue modificada mientras esperaba... continuar con proxima entrada..\n");
				}
				//sleep(5);
				printf("liberando semaforo...\n");
				sem_post((sem_t*) & (args[0].shmPtr[i].semaforo));
				//FINALIZA ZONA CRITICA
				savedFlag=1;//levanto el flag para entradas guardada
			}//IF writableFlag=1
			if(savedFlag==1){//evaluo el flag que me dice si se guardo la entrada en la tabla..
				printf("se almacenaron los datos en la entrada %d de la tabla\n",i);
				break;
			}
			else{
				printf("los datos no se guardaron en la entrada %d, continuar con la siguiente....\n",i);
				continue;
			}
			//el codigo aqui no hace nada debido al continue del else anterior...

		}//FOR: lazo for para almacenar los datos en las entradas
		//verifico que paso al final tras completar el for:
		if(savedFlag==0){//no se guardo en NINGUNA entrada
			printf("LOG: WARNING: la trama no pudo almacenarse en ninguna entrada de la tabla...\n");
			//Aca podria desencadenar un procedimiento en el que se solicita a un administrador de tabla
			//que haga un mantenimiento de la misma; La comunicacion podria ser por pipe.
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
				

	//FINALIZA LA BUSQUEDA DE LUGAR EN LA TABLA

		//AHORA CHEQUEO SI EL ASKER EXISTE EN LA TABLA DE ASKERS.. 

		
			//SI EXISTE LE AUMENTO EL HIT
			//SI NO EXISTE LO AÑADO A LA TABLA
			//solo en el caso de que haya sido una pregunta...:
			if(askFlag==0){
//				return;
			}



int askerFounded=0;
		
		for(i=0,savedFlag=0;i<ARPASKERS_TABLE_SIZE;i++){
			printf("buscando %s en la tabla de askers\n",arpSrcIp);

			//chequear si coincide
			//1| si la entrada esta en NULL entonces esta vacia, saltar a la siguiente
			if(args[0].arpAskers_shmPtr[i].ip==NULL){
				printf("entrada vacia, saltar a la proxima porque estoy comparando nada mas...\n");
				continue;
			}
			else{//si entra aca hay algo en la entrada..compararlo entonces con la arpSrcIp que tengo
				printf("comparando aqui por no ser null: %s contra %s \n", args[0].arpAskers_shmPtr[i].ip,arpSrcIp);
				//OJO que tengo que ver que tengan el mismo strlen para asegurarme de que puedo hacer la comparacion strncmp
				//sino, por ejemplo si comparo 1.1.1.111 con 1.1.1.1 con strlen(1.1.1.1) me van a dar iguales!!!
				if(strlen(arpSrcIp) == strlen(args[0].arpAskers_shmPtr[i].ip)){
					printf("tienen el mismo largo, pueden ser iguales, asi que las comparo...\n");
				}
				else{
					printf("tienen diferente largo.. asi que son diferentes.. no comparo nada sin distitnas y punto\n");
					continue;
				}
				if(!strncmp(args[0].arpAskers_shmPtr[i].ip,arpSrcIp,strlen(arpSrcIp))){
					printf("la entrada ya existe en la tabla...comprobar MAC\n");
					printf("compare %s con %s \n",args[0].arpAskers_shmPtr[i].mac,arpSrcMac);
					if(!strncmp(args[0].arpAskers_shmPtr[i].mac,arpSrcMac,strlen(arpSrcMac))){
						printf("definitivamente la entrada ya existe.. romper bucle\n");
						askerFounded=1;//lo encontre!! levanto flag
						break;
					}
					else{
						printf("Tenemos o bien un nuevo host reemplazando a uno viejo o bien un caso de ip duplicado\n");
//NO VA ACA!						printf("LOG: host reemplazado en tabla asker, posible caso de IP duplicada en la red\n");
						//ACA podria escribir directamente en el pipe hacia el PADRE para informar el WARN
						//o escribir en la tabla de WARNINGS
					}
				}//cierre del if de comparacion de ip en tabla asker y frame actual
				else{
					printf("existia algo en la tabla pero %s no es lo mismo que %s\n",args[0].arpAskers_shmPtr[i].ip,arpSrcIp);
				}
			}//else NO esta vacia la entrada
		}//Lazo for que recorre las entradas de la tabla de arpAskers
		//Si al terminar este for no se encontro la entrada en la tabla, entonces la almaceno!!!

		if(askerFounded!=0){
			printf("El asker estaba en la tabla, asi que no lo guardo nada...\n");
			//continue;//no funciona el continue aqui dentro...
			//aumentar el HIT??
			return;
		}
		//la idea es que no se ejecute el codigo de abajo si NO hay que guardar al asker...por eso el return anterior
		else{
			printf("no se encontro al asker, asi que tengo que guardarlo\n");
		}
		//Recorrer buscando uno VACIO o iniciar algoritmo de insercion cuando la tabla esta llena
int askerSaved=0;

		for(i=0,savedFlag=0;i<ARPASKERS_TABLE_SIZE;i++){
			printf("buscando una entrada vacia para guardar %s en la tabla de askers\n",arpSrcIp);
			if(args[0].arpAskers_shmPtr[i].ip==NULL){
				printf("entrada %d esta vacia, guardando asker...\n",i);
				//Guardar...
				sem_wait((sem_t*) & (args[0].arpAskers_shmPtr[i].semaforo));
				args[0].arpAskers_shmPtr[i].ip=(char *)malloc (strlen(arpSrcIp));
				strcpy(args[0].arpAskers_shmPtr[i].ip,arpSrcIp);
				args[0].arpAskers_shmPtr[i].mac=(char *)malloc (strlen(arpSrcMac));
                                strcpy(args[0].arpAskers_shmPtr[i].mac,arpSrcMac);
				//no voy a usar el index, prefiero chekear bien.. por si se da el caso de reemplazo de asker y yo todabia tengo
					//dialogos en la tabla para chekear, en ese caso deberia descartar ESOS dialogos y dejar los nuevos y por supuesto
					//generar la alerta correspondiente!!
				sem_post((sem_t*) & (args[0].arpAskers_shmPtr[i].semaforo));
				printf("almacenado de la entrada de asker completada...\n");//podria compararlo leyendo la entrada y strncmp con arpSrcip...
				askerSaved=1;//levanto flag de asker almacenado
				break;//porque si ya lo guarde ya esta.. no quiero continuar..
			}
		}//lazo for que ALMACENA el asker si hay entradas vacias

		if(askerSaved==0){
			printf("no se pudo almacenar al asker.. quiza la tabla este llena\n");
			printf("en realidad esta situacion no deberia ocurrir por principio... si estamos aca no funciono el algoritmo de actualizacion\n");
			//Sucede que cuando la tabla esta llena es porque TODAS las ip del rango estan almacenadas.
			//Lo que va a pasar seguro es que si cambio un host por uno nuevo, va a cambiar la MAC pero la ip sera la del viejo host
			//En este caso, lo que tengo que hacer es evaluar cuando encuentro al asker en la tabla -> si la MAC coincide para saber
			//Si se trara o no del MISMO host. caso de ser distintos siempre almaceno el ultimo y genero una alerta en el LOG.
			//El sentido de la alerta es que podria tratarse de IP duplicada o bien de un cambio de host pero debe informarse porque
			//Ha sido descartada la entrada anterior por la nueva!!
		}
		else{
			printf("Se ingreso al asker en la tabla\n");
		}
		//FIN MANEJO DE ASKER TABLE

		//puedo continuar con el proximo frame =) finaliza la tarea de la Callback
		//aumenta el contador de frames
	
	}//ELSE VIAJA ARP
}//definicion de la funcion
