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
	char* target;
	char* iface;
	//ojo abajo: en el caso del mac2guard lo hace dentro del arper a esto XD con el strcpy XD
	char arperIface[10];//por problema que no reconoce el arper el argumento a no ser que sea hardcodeado
	char arperTarget[15];//por lo mismo que con el anterior

	//mas adelante, la idea es que devuelva int de salida, pero pasarle un puntero para que setee los parametros en una estructura.
	printf("------------parser: \n");
	parser(argv[1], &mac2guard, &power, &target, &iface);
	//mac2guard="aa-bb-cc-dd-ee-ff";
	printf("Variables seteadas por el parser: MAC: %s\nTARGET: %s\n,IFACE: %s\n",mac2guard,target,iface);
	printf("------------arpeador: \n");
	int i=0;
	//aqui abajo la magia de la que hablaba en la definicion de variables...
	strcpy(arperIface,iface);
	strcpy(arperTarget,target);
	for(i=0;i<power;i++){
		arper(mac2guard,arperIface,arperTarget);
	}
	//fin
	return 0;
}
