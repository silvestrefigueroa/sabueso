//Este fichero es para poner la estructura que desde el sabueso seteo para pasar los argumentos a la funcion calback del hilo capturador de tramas robadas
//Silvestre E. Figueroa @ FI-UM 2012-2013
//Define here the portStealCaptureThreafsFunction_pcapCallbackArguments struct
typedef struct {
        int tableSize;
        char title[255];
        struct arpDialog* shmPtr;//puntero al array de arpDialog = seria la arpDialoguesTable
}portSCTA_pcapCallbackArgs;
