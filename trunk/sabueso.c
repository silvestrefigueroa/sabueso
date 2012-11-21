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

int main(int argc, char *argv[]){
	if(0>=write(1,BANDERA, strlen(BANDERA)))
		return -1;

	//variables
	char buf[1024];
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
	n=read(fd,buf,sizeof(buf));

	//termina en 0 por ser string
	buf[n]=0;

//	write(1,buf,strlen(buf)); //muestro lo que lei

	//aqui parsear
	char *rightside;
	char *leftside;
	//leftside tiene el primer nombre de comando, rightside tiene el resto
	//podria hacerlo por cada \n tal que me quede \n anidado en " = "
	
	leftside = strtok_r(buf, " = ", &rightside);
	write(1,"izquierda: ",strlen("izquierda: "));
	write(1,leftside,strlen(leftside));
	write(1,"\n",1);
	write(1,rightside,strlen(rightside));



//	sscanf(buf, "%d %s %d", &max_childs, root, &puerto); //parseo del archivo de configuracion
//	printf("hijos: %d\nroot: %s\npuerto: %d\n\n", max_childs, root, puerto);

	//ahora hecho el ojo al buf


	if(0<=write(1,WATCH,strlen(WATCH)))
		return -1;
	sleep(1);
	return 0;
}
