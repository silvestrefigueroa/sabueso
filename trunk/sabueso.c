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
	char *mac2guard, *mac2guard_copy;
	int *power=0;
	char* target;
	char* iface;
	//ojo abajo: en el caso del mac2guard lo hace dentro del arper a esto XD con el strcpy XD
	char arperIface[10];//por problema que no reconoce el arper el argumento a no ser que sea hardcodeado
	char arperTarget[15];//por lo mismo que con el anterior

	parser(argv[1], &mac2guard, &power, &target, &iface);
	printf("\nVariables seteadas por el parser: \nMAC: %s\nTARGET: %s\nIFACE: %s\n",mac2guard,target,iface);
	int i=0;
	//aqui abajo la magia de la que hablaba en la definicion de variables...
	strcpy(arperIface,iface);
	strcpy(arperTarget,target);
	//segun el parametro power, son las veces que enviare frames
	//mas adelante, debo separar la creacion del frame del envio del mismo para no repetir tooooodo por cada iteracion
	
	for(i=0;i<power;i++){
//		arper(mac2guard,arperIface,arperTarget);//arper crea el frame y lo envia(separar)
		arper("00:21:5c:33:09:a5",arperIface,arperTarget);//arper crea el frame y lo envia(separar)
	sleep(1);
	}
	//fin
	write(1,"FIN OK\n",sizeof("FIN OK\n"));
	return 0;
}
