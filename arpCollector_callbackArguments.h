//Este fichero es para poner la estructura que desde el sabueso seteo para pasar los argumentos a la funcion calback del arpCollector
//Silvestre E. Figueroa @ FI-UM 2012-2013
//Define here the arpCollector's Callback's Arguments.
typedef struct {
        int id;
        char title[255];
        struct arpDialog* shmPtr;//puntero al array de arpDialog = seria la arpDialoguesTable
}arpCCArgs;//arpCollectorCallbackArguments
