#include <unistd.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

//MIS PROPIAS CABECERAS
//#include "sabueso.h"
#include "arper.h"

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
#define ERR_CONF_POWER "**Error en el parametro power: muchos frames para enviar!!!\n\n"
//Aqui comienza la magia =)
int parser(char* file_path, char** parsedMac2guard, int** power, char** parsedTarget, char** parsedIface){
	if(0>=write(1,BANDERA, strlen(BANDERA)))
		return -1;
	//variables
	char bufConf[1024];
	int fd, n;

	//Abro el archivo de configuracion 
	if((fd=open(file_path,O_RDONLY))==-1) {
		write(1,ERR_CONF_FNOTF,sizeof(ERR_CONF_FNOTF));//not found
		exit(EXIT_FAILURE);
	}

	//me va que esta mal. deberia leer con limite esperable y capturar error
	n=read(fd,bufConf,sizeof(bufConf));

	//termina en 0 por ser string
	bufConf[n]=0;

	//desde aqui parsear lo que he leido
	char *rightside;
	char *leftside;
	char *aux;//esta variable explico luego por que
	char *mac2guard, *mode, *target, *iface;
	int largo;
	
	//leftside tiene el primer nombre de comando, rightside tiene el resto
	aux = bufConf;//porque me joroba con char** en el 3° arg de strtok_r =( corregir luego esto

	while((leftside = strtok_r(aux, " = ",&aux))){//Ojo: si en la linea hay solo un enter.. se lo mastica!!!
		if(NULL==(rightside = strtok_r(aux, "\n",&aux))){//ejecuto, asigno y comparo al mismo tiempo
			write(1,ERR_CONF_PARAM,sizeof(ERR_CONF_PARAM));
			return -2;
			break;
		}
		if(((int)strlen(rightside)) < 3){
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
			case 6:
				if(0==strcmp(leftside,"target")){
					//deberia comprobar aqui con expresion regular si la IP esta bien seteada
					printf("valor parseado en la IP: %s",&rightside[2]);
					target=&rightside[2];
				}
			break;

			case 5 : //es POWER? si lo es, representa la cantidad de frames que se van a enviar
				if(0==strcmp(leftside,"iface")){
					printf("aqui va la interface de red\n");
					iface=&rightside[2];
//					continue;//corto aqui porque ya esta el parametro...sino seguiria evaluando el mismo!!
					break;
				}

                                if(0==strcmp(leftside,"power")){
                                      //si es el power, luego validar la derecha y pasarla al programa principal

//corresponde utilizar este metodo con strtol y no atoi!!!! luego repara aqui

/*

  static const char *input ="123abc";
    char *garbage = NULL;
    long value = 0;

//    errno = 0;

    value = strtol(&rightside[2], &garbage, 0);

    printf("The value is %ld, leftover garbage in the string is %s\n, but rightside is: %s",
           value, garbage == NULL ? "N/A" : garbage, rightside);

   */



					
					printf("valorcillo: %d\n",atoi(&rightside[2]));
					*power = (int *)atoi(&rightside[2]);//DEBERIA SCANEFEAR CON EXPRESIONES REGULARES..
					if((1 <(int) *power < '100')){
						//printf("parametro correct: %d\n ",(int) *power);
					}
					else{
						write(1,ERR_CONF_POWER,sizeof(ERR_CONF_POWER));
						return -2;
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
	//puede que aqui debajo este la clave de por que es que falla con los otros parametros
	//observar que aqui trae un char* y lo mete en un char** pero char* , una copia?????
	*parsedMac2guard=mac2guard;
		//entonces probare aplicar el mismo "paseo" de valores a ver si le estaba escapando en el puntero??!??!
	*parsedTarget=target;
	*parsedIface=iface;
	printf("El modo leido es: %s\n", mode);
	//fin del programa
	if(0<=write(1,WATCH,strlen(WATCH)))
		return -1;
	sleep(1);
	return 0;
}
