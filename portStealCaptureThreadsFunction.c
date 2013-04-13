#include <stdlib.h>

void *portStealCaptureThreadsFunction(){
	printf("******************************************************************************funcion del hilo\n");
	sleep(1000);
	return NULL;
}
