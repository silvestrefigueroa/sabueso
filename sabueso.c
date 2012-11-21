#include <unistd.h>
#include <string.h>
//#include "sabueso.h"

#define BANDERA "el sabueso olfatea\n"

int main(void){
	if(0!=write(1,BANDERA, strlen(BANDERA)))
		return -1;
	return 0;
}
