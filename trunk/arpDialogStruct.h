//This is a struct file that defines the format of dialogues table.
//@Silvestre E. Figueroa - FI-UM
//sabueso

struct arpDialog{
	int index;
	sem_t semaforo;
	char* ethSrcMac;
	char* ethDstMac;
	char* arpSrcMac;
	char* arpDstMac;
	char* arpSrcIp;
	char* arpDstIp;
	char* type;
	int doCheckIpI;
	int doCheckSpoofer;
	int doCheckHosts;
	int nextState;
	int hit;
};
