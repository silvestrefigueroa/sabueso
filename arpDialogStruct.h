//This is a struct file that defines the format of dialogues table.
//@Silvestre E. Figueroa - FI-UM
//sabueso

struct arpDialog{
	sem_t semaforo;
	int index;
	char* etherSenderMac;
	char* etherDestinationMac;
	char* arpSenderMac;
	char* arpDestinationMac;
	char* arpSenderIp;
	char* arpDestinationIp;
	int hit;
//	sem_t semaforo;//semaforo, NO puntero (va a semaforear cada ENTRADA de la tabla)
};
