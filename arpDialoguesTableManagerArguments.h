typedef struct{
	int id;
	char title[255];
	struct arpDialog* shmPtr;
	int *fdshm;
	char *packet;
}arpDTMWorker_arguments;
