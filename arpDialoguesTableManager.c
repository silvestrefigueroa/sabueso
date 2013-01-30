//This file implements the function that manage all the arpDialoguesTable information
// and is responsible for arpDialoguesTable data check and charge || check and Alert&Charge
//This function is an Thread-piece execution code.its will be used like an thread creation function parameter =)
//Silvestre E. Figueroa, FI-UM 2013 - Sabueso
//
#include "arpDialoguesTableManagerArguments.h"
#include <stdio.h>
#include <string.h>

void* arpDialoguesTableManager(void *arguments){
//	acc=(int)(((struct Argumentos2 *) argumentos)->accion);//funciona esta referencia

	printf("HILO: muestro packet: \n%s\n",(((arpDTMWorker_arguments *) arguments)->packet));

	//OK, i have the message from arpCollector, then i must to explode and parse it to make more human-readable (maybe usable?) code
	puts("-----------------------------------------------------------------------------------------------------------------------\n");
	int n=0;
	char *a;


	//desde aqui parsear lo que he leido
	char *rightside;
	char *leftside;
	char *aux;//esta variable explico luego por que
	char *mac2guard, *mode, *target, *iface;
	int largo;
	int pasada=0;
	
	aux = (((arpDTMWorker_arguments *) arguments)->packet);//porque me joroba con char** en el 3° arg de strtok_r =( corregir luego esto

	while((leftside = strtok_r(aux, "|",&aux))){//Ojo: si en la linea hay solo un enter.. se lo mastica!!!

		if(NULL==(rightside = strtok_r(aux, "|",&aux))){//ejecuto, asigno y comparo al mismo tiempo
			//write(1,ERR_CONF_PARAM,sizeof(ERR_CONF_PARAM));
			return -2;
			break;
		}
		printf("Valor del left: %s\n Valor del Right: %s\n",leftside,rightside);
/*
		if(((int)strlen(rightside)) < 3){
			write(1,ERR_CONF_PARAM,sizeof(ERR_CONF_PARAM));
			return -2;
		}
		//para saltar basura:
		if(0==strcmp(leftside,""))
			continue;
		//para omitir comentarios:
		if(0==strncmp(leftside,"#",1)){
			//printf("Santando comentario\n");
			continue;//consultar que tan elegante es esto
		}
		
		largo=(int)strlen(leftside);
	*/
		//segun el largo "supongo" que argumento es, asi armo el switch
		//switch(largo){
	}

	
	//Primero como minimo reviso consistencia tipo 0 en la trama y el mensaje ARP
	

	return 0;
}



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
