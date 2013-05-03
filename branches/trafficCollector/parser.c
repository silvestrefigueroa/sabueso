//Para strtok_r y printf
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//para parsear el archivo de configuracion
#include <libconfig.h>


//librerias propias
#include "server2guardStruct.h"

int parse(char *configFileName,server2guardStruct *parametersConf,int mode){//mode: 0 config parameters, 1 servers2guard configuration

//	strncpy(parametersConf->ip,"hola desde el parser",strlen("hola desde el parser"));
//	return 0;

	config_t cfg;
	config_setting_t *setting;
	char *str1=NULL;
	const char *servers2guard=NULL;
	const char *str2=NULL;
	int j=0;//contado strtok_r
	char *saveptr1=NULL;
	char *token=NULL;


	
	//printf("PARSER: el nombre de fichero recibido desde el sabueso es: %s\n",configFileName);
	char *config_file_name = configFileName;

	//Initialization
	config_init(&cfg);

	//Leer el archivo, si hay un error reportarlo y salir
	if(!config_read_file(&cfg, config_file_name)){
//		printf("\n%s:%d - %s", config_error_file(&cfg), config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return -1;
	}



	switch(mode){
		case 0://MODO DE LECTURA DE PARAMETROS DE CONFIGURACION
			puts("PARSER: modo config parameters\n");

			const char *iface=NULL;


			/* Get the NIC name. */
			if(config_lookup_string(&cfg, "iface", &iface)){
				printf("PARSER: Network interface selected by user: %s\n", iface);
			}
			else{
				printf("No valid value for iface provided in configuration file.\n");
			}

			//obtener la lista de servers2guard
			if(config_lookup_string(&cfg, "servers2guardList", &servers2guard)){
				printf("Server2guard:  %s\n", servers2guard);
			}
			else{
				printf("No valid value for servers2guard provided in configuration file.\n");
			}

			//Parsear la lista y obtener la cantidad de servers2guard para devolver el parametro de tamaño de la shm para los servers2guard

			for(j=1,str1 = (char *)servers2guard; ; j++, str1=NULL){
				token=strtok_r(str1,",",&saveptr1);
				if(token==NULL){
					break;
				}

			}//cierra for que recorre la a lista y la parsea

			strncpy(parametersConf->ip,iface,strlen(iface));//dispositivo de red seleccionado
			parametersConf->tos=(j-1);//cantidad de servers (para dimensionar la tabla de servers2guard o serversQuantity =)

			//BIEN, EL PROXIMO PASO SERA LLAMAR DE NUEVO AL PARSER PERO EN MODO 1
		break;
		//-------------------------------------------------------------------------------------------------------------------------------------
		case 1://MODO DE SETEO DE SERVERS2GUARD EN LA SHM
			puts("PARSER: modo servers2guard config\n");


			strncpy(parametersConf[0].ip,"holita",strlen("holita"));
			return 0;


			//AHORA EN LO QUE SE TRAJO EN SERVERS2GUARD, PARSEO POR , Y PARA CADA UNO, EJECUTO LA LECTURA DE GRUPO:

			const char *ip=NULL;
			const char *mac=NULL;
			long int serviceType=0;
			for(j=1,str1 = (char *)servers2guard; ; j++, str1=NULL){
				token=strtok_r(str1,",",&saveptr1);
puts("antes de breakear\n");
				if(token==NULL){
					break;
				}
				printf("---------------------------------\n");

				printf("\n\nServerName: %s\n",token);

	puts("aca\n");

				//Read the parameter group
				setting = config_lookup(&cfg, token);
				if(setting != NULL){
					//Read the string
puts("aca adentro\n");
					if(config_setting_lookup_string(setting, "description",&str2)){
						printf("description: %s\n", str2);
					}
					else{
						printf("No valid 'description' setting in configuration file.\n");
					}

					if(config_setting_lookup_string(setting, "ip",&ip)){
						printf("ip: %s\n", ip);
					}
					else{
						printf("No valid 'servername' setting in configuration file.\n");
					}

					if(config_setting_lookup_string(setting, "mac",&mac)){
						printf("mac: %s\n", mac);
					}
					else{
						printf("No valid 'mac' setting in configuration file.\n");
					}


					//Read the integer
					if(config_setting_lookup_int(setting, "serviceType", &serviceType)){
						printf("Service Type: %ld\n", serviceType);
					}
					else{
						printf("No valid 'serviceType' setting in configuration file.\n");
					}
					printf("\n");
					//ALMACENAR LOS DATOS CORRESPONDIENTES DE ESTE HOST EN LA ESTRUCTURA:

					strncpy(parametersConf[0].ip,ip,strlen(ip));//dispositivo de red seleccionado
					puts("asignado\n");




	
				}//if setting no nulll
			}//For j=1.. del strtok_r

		break;
		default:
			puts("PARSER: error en la lectura de parametro de modo (el acceso a disco fue innecesario :/ \n");
			return -1;
		break;
	}//SWITCH MODE

return 0;
}
