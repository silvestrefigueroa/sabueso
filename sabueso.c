#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

//#include "sabueso.h"

//Defino mensajes estaticos (para no hardcodear)
#define BANDERA "el sabueso olfatea\n"
#define WATCH "aqui estoy\n"
#define MSG_USO "uso: sabueso <archivo_de_configuracion>\n"

//Errores de configuracion:
#define ERR_CONF_FNOTF "***Error!!! no se encontro el fichero de configuracion!!! \n"
#define ERR_CONF "**Error al parsear el fichero de configuracion\n"
#define ERR_CONF_MAC "**Error en la MAC especificada, recuerde ingresar espacios antes y despues del \"=\" \n"
#define ERR_CONF_MODE "**Modo seleccionado incorrecto, seleccione modo cazador o modo guardian\n"
#define ERR_CONF_PARAM "**Error en los parametros del archivo de configuracion. respete formato <parametro><sp><=><sp><valor>\n\n"
#define ERR_CONF_UPARAM "**Error en el fichero de configuracion: parametro no reconocido. Consulte la documentacion.\n"

//Aqui comienza la magia =)
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
		//perror("El archivo no existe");		 //si le tiro cualquier fruta
		write(1,ERR_CONF_FNOTF,sizeof(ERR_CONF_FNOTF));
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
	char *mac2guard, *mode;
	int largo;
	
	//leftside tiene el primer nombre de comando, rightside tiene el resto
	
	aux = bufConf;//porque me joroba con char** en el 3° arg de strtok_r =( corregir luego esto

	while((leftside = strtok_r(aux, " = ",&aux))){//Ojo: si en la linea hay solo un enter.. se lo mastica!!!
//		leftside = strtok_r(aux, " = ",&aux); //lo puse en el arg del while asi evalua y corta a la vez :-)

		//si es que puede parsear al lado derecho:
		if(NULL==(rightside = strtok_r(aux, "\n",&aux))){//ejecuto, asigno y comparo al mismo tiempo
			//no pudo parsear
			write(1,ERR_CONF_PARAM,sizeof(ERR_CONF_PARAM));
			return -2;
			break;
		}
		if(((int)strlen(rightside)) < 3){
			//printf("algo esta muuuuuuy malllllllllllllllllll\n\n el size es: %d \n",(int)strlen(rightside));
			write(1,ERR_CONF_PARAM,sizeof(ERR_CONF_PARAM));
			return -2;
		}


		write(1,"izquierda: ",strlen("izquierda: "));
		write(1,leftside,strlen(leftside));
		write(1,"\n",1);

		write(1,"derecha: ",strlen("derecha: "));
	        write(1,rightside,strlen(rightside));
	        write(1,"\n",1);

		//muy bonito mostrarlo pero ahora hay que guardarlo!

		//para saltar basura:
		if(0==strcmp(leftside,""))
			continue;
		//para omitir comentarios:
		if(0==strncmp(leftside,"#",1)){
			//printf("Santando comentario\n");
			continue;//consultar que tan elegante es esto
		}
		//seteo los valores a las variables... proximamente seteare a la estructura de argumentos mejor :-)
		
		//es lo mismo leftside que &leftside[0], el subindice le dice desde donde leer
		
		largo=(int)strlen(leftside);
		//printf("tamaño: %d\n ", largo);

		//segun el largo "supongo" que argumento es, asi armo el switch
		switch(largo){
			case 9 : //es mac2guard
				//si el right es menor de 17 esta mal, leo apartir del 2 por " = " son 0,1,2
				//hay que hacer bien este parser, si le tiro " =aaa:bb..." no se queja de la primer "a" ajajaja
				//printf("case 9 leftside= %s\n",leftside);
				//printf("comparacion: %d\n",(strcmp(leftside,"mac2guard")));

				if(0==strcmp(leftside,"mac2guard")){
					//printf("iguales!!!\n");
					//se que parametro es: mac2guard
					//reviso que el valor este bien
					if(strlen(&rightside[2])!=17){//revisa el largo, añadir validaciones aqui porque es insuficiente!!usar exp.regular
						write(1,ERR_CONF_MAC,sizeof(ERR_CONF_MAC));
						return -2;
					}
					else{//else acepto la MAC (si paso las validaciones, en este caso SOLO el largo)
						mac2guard=&rightside[2];
						//printf("\n tamaño seteado: %d\n", (int)strlen(mac2guard));
					}
				}
			break;
			case 4 : //es mode??? compruebo
                                //aplican las mismas ideas que en el de mac2guard
                                //printf("case 4 leftside= %s\n",leftside);
                                //printf("comparacion: modoooo: %d\n",(strcmp(leftside,"mode")));

                                if(0==strcmp(leftside,"mode")){
                                        //printf("iguales!!!\n");
                                        //se que parametro es: mode
                                        //reviso que el valor este bien: mode puede ser: guardian o cazador
					//guardian: actua como el snort, snifeando todo lo que pasa por el nada mas
					//cazador: esta atento a los dialogos de mac2guard, va e investiga...
                                       if(0==strcmp(rightside,"guardian")){//strcmp de momento.. son solo 2 modos.
						//printf("Modo guardian seleccionado\n");
						mode="guardian";
                                        }
                                        else{
						if(0==strcmp(&rightside[2],"cazador")){//porque omito los 3 primero de " = "
						//mode cazador
							//printf("mode cazador!! \n");
							mode="cazador";
						}
						else{
							//mode incorrecto
							mode="UNKNOWN";
							write(1,ERR_CONF_MODE,sizeof(ERR_CONF_MODE));
							return -2;
						}
                                        }
                                }
				else{
					//otro parametro de 4
					write(1,ERR_CONF_UPARAM,sizeof(ERR_CONF_UPARAM));
					return -2;
				}
			break;
			default:
				write(1,ERR_CONF_UPARAM,sizeof(ERR_CONF_UPARAM));
				printf("no reconocido\n");
				return -2;
			break;

		}
	}
	printf("La MAC leida es: %s\n", mac2guard);
	printf("El modo leido es: %s\n", mode);
	//fin del programa
	if(0<=write(1,WATCH,strlen(WATCH)))
		return -1;
	sleep(1);
	return 0;
}
