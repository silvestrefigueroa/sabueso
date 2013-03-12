//This is a struct file that defines the format of asker struct that is stored into a arpAskersTable
//@Silvestre E. Figueroa - FI-UM
//sabueso
//Esta es una entrada de la tabla de hosts "preguntones" que voy a mantener compartida y sincronizada.

typedef struct{
	sem_t semaforo;
	int arpAskerIndex;
	char* mac;
	char* ip;
	char* status;
	int hit;
}arpAsker;
