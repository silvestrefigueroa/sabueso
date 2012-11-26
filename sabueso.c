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

//MENSAJES ESTATICOS
#define MSG_START "Comienza aqui el programa principal\n"

//Aqui comienza la magia =)
int main(int argc, char *argv[]){
	if(0>=write(1,MSG_START, strlen(MSG_START)))
		return -1;

	//parseo el fichero de configuracion
	//0->mac2guard,1->iface,2->target_ip,3->mode

	//mas adelante, la idea es que devuelva int de salida, pero pasarle un puntero para que setee los parametros en una estructura.
	printf("------------parser: \n");
	parser(argv[1]);
	printf("------------arpeador: \n");
	arper("aa:aa:aa:ff:ff:ff", "wlan0","192.168.1.114");
	//fin
	return 0;
}	
