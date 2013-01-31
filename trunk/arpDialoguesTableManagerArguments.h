typedef struct{
	int *fdshm;
	struct arpDialog** shmPtr;//sharedMem pointer
	char *packet;
}arpDTMWorker_arguments;
