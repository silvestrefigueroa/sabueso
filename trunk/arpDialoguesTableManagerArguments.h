typedef struct{
	int id;
	char title[255];
	struct arpDialog* shmPtr;
	int *fdshm;
	char *packet;
	char *ethSrcMac;
	char *ethDstMac;
	char *arpSrcMac;
	char *arpDstMac;
	char *arpSrcIp;
	char *arpDstIp;
}arpDTMWorker_arguments;
