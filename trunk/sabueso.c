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

	//variables de datos del programa principal
	char *mac2guard;
	int *power=0;
	const char* target;
	const char* iface; //si no es const explota porque no reconoce wlan0 como nombre de placa de red como si lo haria hardcodeando "wlan0" en header
	
	//mas adelante, la idea es que devuelva int de salida, pero pasarle un puntero para que setee los parametros en una estructura.
	printf("------------parser: \n");
	parser(argv[1], &mac2guard, &power, &target, &iface);
	//mac2guard="aa-bb-cc-dd-ee-ff";
	printf("maccccc: %s \n\n",mac2guard);
	printf("------------arpeador: \n");
	int i=0;
	for(i=0;i<power;i++){
		arper(mac2guard,"wlan0","192.168.1.1");
	}
	//fin
	return 0;
}
