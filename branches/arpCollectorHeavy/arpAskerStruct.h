//This is a struct file that defines the format of asker struct that is stored into a arpAskersTable
//@Silvestre E. Figueroa - FI-UM
//sabueso
//Esta es una entrada de la tabla de hosts "preguntones" que voy a mantener compartida y sincronizada.

typedef struct{
	sem_t semaforo;
	int arpAskerIndex;
	char mac[40];
	char ip[40];
	int status; //podria utilizarlo para indicar que esta en monitoreo actualmente o bien para indicar incidencia onda que esta en WARN
	int hit;
}arpAsker;
