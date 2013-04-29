#include <stdio.h>
#include <libconfig.h>

int parse(char *configFileName){
	config_t cfg;
	config_setting_t *setting;
	const char *str1=NULL;
	const char *str2=NULL;
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
	if(config_lookup_string(&cfg, "iface", &str1)){
		printf("\nNetwork interface selected by user: %s", str1);
	}
	else{
		printf("\nNo valid value for iface provided in configuration file.");
	}


	/*Read the parameter group*/
	setting = config_lookup(&cfg, "servers2guard");
	if(setting != NULL){
		/*Read the string*/
		if(config_setting_lookup_string(setting, "param1", &str2)){
			printf("\nParam1: %s", str2);
		}
		else{
			printf("\nNo 'param1' setting in configuration file.");
		}
		/*Read the integer*/
		if(config_setting_lookup_int(setting, "param2", &tmp)){
			printf("\nParam2: %ld", tmp);
//			printf("\n param2: %d \n", (int) tmp);
		}
		else{
			printf("\nNo 'param2' setting in configuration file.");
		}
		printf("\n");
	}
	config_destroy(&cfg);
	return 0;
}
