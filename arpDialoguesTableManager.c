//This file implements the function that manage all the arpDialoguesTable information
// and is responsible for arpDialoguesTable data check and charge || check and Alert&Charge
//This function is an Thread-piece execution code.its will be used like an thread creation function parameter =)
//Silvestre E. Figueroa, FI-UM 2013 - Sabueso
//
#include "arpDialoguesTableManagerArguments.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <semaphore.h>
#include "arpDialogStruct.h"


void* arpDialoguesTableManager(void *arguments){

//	printf("HILO: muestro packet: \n%s\n",(((arpDTMWorker_arguments *) arguments)->packet));
//	char* paquete=(((arpDTMWorker_arguments *) arguments)->packet);
	
	//struct arpDialog* shmPtr = (((arpDTMWorker_arguments *) arguments)->shmPtr);

//	printf("imprimite estaaaaaaaa %d\n",(int) shmPtr[43].index);

//	printf("HILADOR: me quedo: %s\n",paquete);

	//OK, i have the message from arpCollector, then i must to explode and parse it to make more human-readable (maybe usable?) code
	puts("¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬¬\n");
	//desde aqui parsear lo que he leido

	puts("soy una hebra\n");
	sleep(10);


//	char* rightside=NULL;
//	char* leftside=NULL;
//	char* aux=NULL;//esta variable explico luego por que
	//para guardar los datos parseados:
//	int pasada=0;
//	int srcMacEquals=1;//coinciden por default
	//reducir la perogruyada de asignacion que hago abajo..no me salio en una sola linea..
	char* ethSrcMac=NULL;
	char* ethDstMac=NULL;
	char* arpSrcMac=NULL;
	char* arpDstMac=NULL;
	char* arpSrcIp=NULL;
	char* arpDstIp=NULL;
//	char* broadcastMac="ff:ff:ff:ff:ff:ff";
//	char* zeroMac="0:0:0:0:0:0";

	ethSrcMac=(((arpDTMWorker_arguments *) arguments)->ethSrcMac);
	ethDstMac=(((arpDTMWorker_arguments *) arguments)->ethDstMac);
	arpSrcMac=(((arpDTMWorker_arguments *) arguments)->arpSrcMac);
	arpDstMac=(((arpDTMWorker_arguments *) arguments)->arpDstMac);
	arpSrcIp=(((arpDTMWorker_arguments *) arguments)->arpSrcIp);
	arpDstIp=(((arpDTMWorker_arguments *) arguments)->arpDstIp);

//	sem_post((sem_t *) & (shmPtr[0].semaforo)); //moverlo arriba para tener lo menos posible este bloqueo


	printf("que se trae el arguments: %s	%s	%s	%s	%s	%s\n",ethSrcMac,ethDstMac,arpSrcMac,arpDstMac,arpSrcIp,arpDstIp);
	return 0;
}


/*
	aux = (((arpDTMWorker_arguments *) arguments)->packet);//porque me joroba con char** en el 3° arg de strtok_r =( corregir luego esto
	while((leftside = strtok_r(aux, "|",&aux))){//Ojo: si en la linea hay solo un enter.. se lo mastica!!!
		if(NULL==(rightside = strtok_r(aux, "|",&aux))){//ejecuto, asigno y comparo al mismo tiempo
			//write(1,ERR_CONF_PARAM,sizeof(ERR_CONF_PARAM));
			puts("aqui hay nulo encerrado!!!\n");
			break;
		}
		printf("Valor del left: %s\n Valor del Right: %s\n",leftside,rightside);

		switch(pasada){
			case 0:
				//obtengo las mac del frame ethernet
				//puts("pasada 0\n");
				ethSrcMac=leftside;
				ethDstMac=rightside;
				//a[0]=leftside;
				//a[1]=rightside;
			break;
			case 1:
				//obtengo las mac del ARP message
				//puts("pasada 1\n");
				arpSrcMac=leftside;
				arpDstMac=rightside;
				//a[2]=leftside;
				//a[3]=rightside;
			break;	
			case 2:
				//obtengo las IP del ARP message
				//puts("pasada 2\n");
				arpSrcIp=leftside;
				arpDstIp=rightside;	
			break;
			default:
				//error!!
			break;
				
		}
		pasada++;

	}//fin parseo de paquete

*/

/*	

	
	//Ahora como minimo reviso consistencia tipo 0 en la trama y el mensaje ARP
	if(*ethSrcMac!=*arpSrcMac){
		printf("se ha detectado inconsistencia entre la MAC origen de la trama y la MAC origen del mensaje ARP\n");//podria ser proxyARP???
		printf("Son realmente distintos %s y %s  ??\n",ethSrcMac,arpSrcMac);
		//desde ya establezco que la trama es inconsistente en la direccion MAC de origen
		srcMacEquals=0;//ya que por default coinciden...
	}
	else{//nada... esta ok punto.
		printf("ethSrcMac=arpSrcMac     OK\n");
	}
	if(*ethDstMac!=*arpDstMac){
		//si difieren en la MAC destino pero es el caso particular del broadcast, entonces me aseguro!!
		printf("entonces %s es distinto de %s\n",ethDstMac,arpDstMac);
		puts("siguio...\n");
		printf("aaaaaaaaaaa tengo: %s y %s \n\n",ethDstMac,"ff:ff:ff:ff:ff:ff");
		if(*ethDstMac==*broadcastMac){
			puts("ethDsrMac es broadcast!!!\n");
			//mmm iba al broadcast, sera una pregunta realmente? o sera para engañar?
			if(*arpDstMac==*zeroMac){//si es una pregunta ARP, lo marco para consultar su credibilidad? o consulto yo?
				//OK, es ARP request (al menos por la formacion)
				//es al menos una trama aceptable, podria verificarse luego pero al menos la acepto asi!
				//verifico si la IP de destino coincide con la del host que tiene la MAC ethDstMac
				//si quiero realmente probar esto, deberia chequear los pares MACIP de cada host participante
				printf("puede que sea una pregunta ARP legitima..\n");//faltaria verificar match de ip-mac origen.
			}
			else{//Si entra aqui, es porque fue al broadcast, pero el ARP tiene un destino FIJO, es muy extraño!!
				printf("caso extraño, ethDstMac broadcast y arpDstMac Unicast...anomalo!!\n\n");
				//podria verificar el match IP-MAC origen, es un caso para WARN no para evaluarlo porque no viene al caso por ahora.
			}
		}
		else{//para los casos que no son broadcast en ethernet

			//destino ethernet bien definido, pero MAC destino en ARP DISTINA!!MALFORMACION!!
			//Este curioso caso se da por ejemplo con el DDwrt. el destino en ARP debera ser 0:0:0:0:0:0
			printf("antes de comparar con zero, tengo %s y %s\n",arpDstMac,zeroMac);
			if(*arpDstMac==*zeroMac){
				//es altamente probable que sea una preguntita del AP que se hace el que no sabe quien es el cliente
				//para confirmar, valido ethSrcMac con arpSrcMac y luego arpSrcMac con arpSrcIp =)
				printf("Posible mensaje del AP, compruebe que ethSrcMac matchea con arpSrcIp para descartar ataque DoS\n");
				//tratar el error o escapar si OK
				//WARNING, marcar para comprobar y almacenar.
			}
			//el else de abajo OJO, porque queda el resto en el que las 4 mac son iguales!!
			else{//se trata de MACs destinos AMBIGUOS, es una trama anomala!! a no ser que sea del proxyARP
				printf("Trama con destino definido, revisando en profundidad....Posible ProxyARP\n\n");
				//tratar mas este caso o indicar error!!
			}
		}
	}
	else{//macs destino coinciden, o sea bien dirigido..puede ser una trampa, si el origen tiene spoofeada la IP es la trama del atacante
		//o bien son tramas ARP que cayeron en el filtro (y vienen del portstealing) pero spoofeadas tambien por que no?
		//primero que nada chekeo si las MAC origen son iguales (primer verificacion, leo el resultado directamente)
			//si son iguales, veo el match MAC-IP del origen para ver si es ataque (consulto info real)
			switch(srcMacEquals){
				case 1:
					//trama OK, debera verificar capa de red IP
						//si no matchea, entonces ALERTO EL ATAQUE!!!
						//SI MATCHEA, tenemos origen OK, destino OK.... nada raro.. me robe un ARP..
						printf("trama aparentemente normal, marcada para chekear IP\n");
						//marcar para portstelear y GUARDAR el dialogo en la tabla
				break;
				case 0:
						//no son iguales las MAC origen
						//Puede ser proxyARP????(ojo que esta filtrado) o bien el origen (sender) esta haciendo algo raro
						//WARNING-> inconsistencia en las MAC origen
						printf("macs origen no coinciden, posible proxyARP o trama anomala\n");
				break;
				default:
					printf("caso anomalo no tratado, no pudo determinarse igualdad de mac origen\n");
				break;
			}
	}
//	sem_post((sem_t *) & (shmPtr[0].semaforo)); //moverlo arriba para tener lo menos posible este bloqueo

	return 0;
}

*/


















/*


		//Lo almaceno en la tabla de dialogos =)

		//Evaluo la existencia previa en arpDialoguesTable
			//Para ello implementar mecanismos de hash para la indizacion y comparacion (agil)
				//Si la entrada existe y es consistente -> no la almaceno en la tabla
					//Procedimiento y break
				//SI existe pero no es consistente -> evaluo tipo de inconsistencia
					//Procedimiento y almacenamiento y break
				//Si no existe, chequear consistencia y continuar
			//Continuar...




				//EJEMPLO: Evaluo ientegridad de la trama completa:

				//primero me fijo si la MAC origen de la trama es igual a la MAC origen del ARP
				if((ether_ntoa((const struct ether_addr*) eptr->ether_shost))!=(ether_ntoa((const struct ether_addr*) arpPtr->arp_sha))){
					printf("PROBLEMAS.. NO COINCIDEN LAS SOURCE MAC!!!\n");
					//generar alerta
				}
		//lanzar un hilo que se encargue de buscar en toda la tabla entradas que validen la relacion de macIP presentadas en esta trama
		//luego si no hay alerta de ningun tipo, generar los hashes y cargarla en la tabla.

*/
