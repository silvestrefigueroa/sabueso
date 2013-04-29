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
	long int tmp=0;
	
	printf("PARSER: el nombre de fichero recibido desde el sabueso es: %s\n",configFileName);
	char *config_file_name = "sabueso.conf";

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
		printf("\nNetwork interface selected by user: %s", iface);
	}
	else{
		printf("\nNo valid value for iface provided in configuration file.");
	}

	if(config_lookup_string(&cfg, "servers2guardList", &servers2guard)){
		printf("\nServer2guard:  %s", servers2guard);
	}
	else{
		printf("\nNo valid value for servers2guard provided in configuration file.");
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
		printf("%d: %s\n", j, token);
	}






	//Read the parameter group
	setting = config_lookup(&cfg, "serverweb");
	if(setting != NULL){
		//Read the string






		if(config_setting_lookup_string(setting, "servername",&str2)){
			printf("\nservername: %s", str2);
		}
		else{
			printf("\nNo valid 'servername' setting in configuration file.");
		}
/*
		if(config_setting_lookup_string(setting, "ip",&ip)){
			printf("\nip: %s", ip);
		}
		else{
			printf("\nNo valid 'servername' setting in configuration file.");
		}

*/



		//Read the integer
		if(config_setting_lookup_int(setting, "param2", &tmp)){
			printf("\nParam2: %ld", tmp);
//			printf("\n param2: %d \n", (int) tmp);
		}
		else{
			printf("\nNo 'param2' setting in configuration file.");
		}
		printf("\n");
	}

	return 0;
}
