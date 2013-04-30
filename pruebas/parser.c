//Para strtok_r y printf
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//para parsear el archivo de configuracion
#include <libconfig.h>

int parse(char *configFileName){
	config_t cfg;
	config_setting_t *setting;
	char *str1=NULL;
	const char *iface=NULL;
	const char *servers2guard=NULL;
	const char *str2=NULL;
	const char *ip=NULL;
	const char *mac=NULL;
	long int serviceType=0;
	
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

	/* Get the configuration file name. */
	if(config_lookup_string(&cfg, "iface", &iface)){
		printf("Network interface selected by user: %s\n", iface);
	}
	else{
		printf("No valid value for iface provided in configuration file.\n");
	}

	if(config_lookup_string(&cfg, "servers2guardList", &servers2guard)){
		printf("Server2guard:  %s\n", servers2guard);
	}
	else{
		printf("No valid value for servers2guard provided in configuration file.\n");
	}

	//AHORA EN LO QUE SE TRAJO EN SERVERS2GUARD, PARSEO POR , Y PARA CADA UNO, EJECUTO LA LECTURA DE GRUPO:

	int j=0;//contado strtok_r
	char *saveptr1=NULL;
	char *token=NULL;
	for(j=1,str1 = (char *)servers2guard; ; j++, str1=NULL){
		token=strtok_r(str1,",",&saveptr1);
		if(token==NULL){
			break;
		}
		printf("---------------------------------\n");

		printf("\n\nServerName: %s\n",token);

		//Read the parameter group
		setting = config_lookup(&cfg, token);
		if(setting != NULL){
			//Read the string

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
		}//if setting no nulll
	}//For j=1.. del strtok_r
	printf("---------------------------------\n");

	return 0;
}
