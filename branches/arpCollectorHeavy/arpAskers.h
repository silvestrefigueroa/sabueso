//This is a struct file that defines the format of asker struct that is stored into a arpAskersTable
//@Silvestre E. Figueroa - FI-UM
//sabueso

typedef struct{
	sem_t semaforo;
	char* mac;
	char* ip;
	char* status;
	int hit;
}arpAsker;
