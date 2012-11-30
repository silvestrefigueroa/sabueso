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
	//mas adelante, la idea es que devuelva int de salida, pero pasarle un puntero para que setee los parametros en una estructura.
	printf("------------parser: \n");
	parser(argv[1]);
	char *mac2guard;
	mac2guard="aa-bb-cc-dd-ee-ff";
	printf("mac: %s \n\n",mac2guard);
	printf("------------arpeador: \n");
	int i=0;
	for(i=0;i<1;i++){
		arper(mac2guard, "wlan0","192.168.1.1");
	}
	//fin
	return 0;
}	
