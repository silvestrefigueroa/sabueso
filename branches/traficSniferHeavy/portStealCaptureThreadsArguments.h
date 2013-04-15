//Este fichero es para poner la estructura que desde el sabueso seteo para pasar los argumentos a la funcion que ejecutan los hilos del portstealer
//Silvestre E. Figueroa @ FI-UM 2012-2013
//Define here the port stealer capturer thread function Arguments.
typedef struct {
        int tableIndex;
	pcap_t* descr;//descriptor de la captura
        struct bpf_program fp;//aca se guardara el programa compilado de filtrado
	bpf_u_int32 netp;//direccion de red
	int tableSize;
	//otros atributos de la estructura
}portStealCaptureThreadsArguments;//arpCollectorCallbackArguments
