//This is a struct file that defines the format of dialogues table.
//@Silvestre E. Figueroa - FI-UM
//sabueso

//esta estructura define el formato de las entradas de la tabla de dialogos que se guarda en la memoria compartirda.
//La memoria compartida es una estructura donde uno de los campos es un array de estas estructuras, es decir, una tabla.

struct arpDialog{
	int arpAskerIndex;//el numero de entrada en tabla arpAsker que contiene al arpSrcMac de esta entrada
	sem_t semaforo;
	char* ethSrcMac;
	char* ethDstMac;
	char* arpSrcMac;
	char* arpDstMac;
	char* arpSrcIp;
	char* arpDstIp;
	int type;
	int doCheckIpI;
	int doCheckSpoofer;
	int doCheckHosts;
	int nextState;
	int hit;
};
