#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
//#include <string.h>
#include <fcntl.h>



//#include "sabueso.h"


//Defino mensajes estaticos (para no hardcodear)
#define BANDERA "el sabueso olfatea\n"
#define WATCH "aqui estoy\n"
#define MSG_USO "uso: sabueso <archivo_de_configuracion>\n"
#define ERR_CONF "Error al parsear el fichero de configuracion\n"

int main(int argc, char *argv[]){
	if(0>=write(1,BANDERA, strlen(BANDERA)))
		return -1;

	//variables
	char bufConf[1024];
//	char mac2guard[1024]={};
	int fd, n;

	if(argc==1)
		if(0>=write(1,MSG_USO,strlen(MSG_USO)))
			return -1;
	assert(argc==2);

	//Abro el archivo de configuracion 
	if((fd=open(argv[1],O_RDONLY))==-1) {
		perror("El archivo no existe");		 //si le tiro cualquier fruta
		exit(EXIT_FAILURE);
	}

	//me va que esta mal. deberia leer con limite esperable y capturar error
	n=read(fd,bufConf,sizeof(bufConf));

	//termina en 0 por ser string
	bufConf[n]=0;

//	write(1,buf,strlen(buf)); //muestro lo que lei

	//desde aqui parsear lo que he leido

	char *rightside;
	char *leftside;
	char *aux;//esta variable explico luego por que
	char mac2guard, mode;
	
	//leftside tiene el primer nombre de comando, rightside tiene el resto
	
	aux = bufConf;//porque me joroba con char** en el 3° arg de strtok_r =( corregir luego esto

	while((leftside = strtok_r(aux, " = ",&aux))){
//		leftside = strtok_r(aux, " = ",&aux); //lo puse en el arg del while asi evalua y corta a la vez :-)
		rightside = strtok_r(aux, "\n",&aux);

		write(1,"izquierda: ",strlen("izquierda: "));
		write(1,leftside,strlen(leftside));
		write(1,"\n",1);

		write(1,"derecha: ",strlen("derecha: "));
	        write(1,rightside,strlen(rightside));
	        write(1,"\n",1);

		//muy bonito mostrarlo pero ahora hay que guardarlo!

		//para omitir comentarios:
		//if(leftside[0]=="#")
		//	break;
		//seteo los valores a las variables... proximamente seteare a la estructura de argumentos mejor :-)
		switch (leftside) {
			case "mac2guard":
				mac2guard=rightside;
				break;
			case "mode":
				mode = rightside;
				break;
			default:
				f(0>=write(1,ERR_CONF,strlen(ERR_CONF)))
	                        return -2;
				break;
		}
	}
	//fin del programa
	if(0<=write(1,WATCH,strlen(WATCH)))
		return -1;
	sleep(1);
	return 0;
}
