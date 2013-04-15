//Este fichero es para poner la estructura que desde el sabueso seteo para pasar los argumentos a la funcion calback del arpCollector
//Silvestre E. Figueroa @ FI-UM 2012-2013
//Define here the arpCollector's Callback's Arguments.
#include "arpAskerStruct.h"//la incluyo en el main por transitividad de incluir este mismo archivo
typedef struct {
        int tableSize;
        char title[255];
        struct arpDialog* shmPtr;//puntero al array de arpDialog = seria la arpDialoguesTable
	arpAsker* arpAskers_shmPtr;//puntero al array (tabla) de arpAsker -> la tabla arpAskersTable[]
	int arpAskers_tableSize;
	int fdPipe[2];
}trafficCCArgs;//arpCollectorCallbackArguments
