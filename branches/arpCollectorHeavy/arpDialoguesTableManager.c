//This file implements the function that manage all the arpDialoguesTable information
// and is responsible for arpDialoguesTable data check and charge || check and Alert&Charge
//This function is an Thread-piece execution code.its will be used like an thread creation function parameter =)
//Silvestre E. Figueroa, FI-UM 2013 - Sabueso
//
#include "arpDialoguesTableManagerArguments.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <semaphore.h>
#include "arpDialogStruct.h"


void* arpDialoguesTableManager(void *arguments){

	printf("-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-_-\n");
	int srcMacEquals=1;//coinciden por default
	//reducir la perogruyada de asignacion que hago abajo..no me salio en una sola linea..
	char* ethSrcMac=NULL;
	char* ethDstMac=NULL;
	char* arpSrcMac=NULL;
	char* arpDstMac=NULL;
	char* arpSrcIp=NULL;
	char* arpDstIp=NULL;
	char* broadcastMac="ff:ff:ff:ff:ff:ff";//Estara mal esto? no deberia inicializar a null y luego cargarle esta cadena?no deberia reservar?
	char* zeroMac="0:0:0:0:0:0";//lo mismo que el anterior
	int doCheckIpI=0;
	int doCheckSpoofer=0;
	int doHitIncrement=0;
	int nextState=0;//por default, almacenarla y ya
	char* type=NULL;//consultar posibles valores en tabla_de_dialogos.txt [Arquitectura]
	int i=0;
	int dstZeroMacFlag=0;
	int dstBrdMacFlag=0;

	//mapear los datos para facilitar la manipulacion de los mismos y el codeado.

	ethSrcMac=(((arpDTMWorker_arguments *) arguments)->ethSrcMac);
	ethDstMac=(((arpDTMWorker_arguments *) arguments)->ethDstMac);
	arpSrcMac=(((arpDTMWorker_arguments *) arguments)->arpSrcMac);
	arpDstMac=(((arpDTMWorker_arguments *) arguments)->arpDstMac);
	arpSrcIp=(((arpDTMWorker_arguments *) arguments)->arpSrcIp);
	arpDstIp=(((arpDTMWorker_arguments *) arguments)->arpDstIp);

	//Ahora como minimo reviso consistencias menores en la trama y el mensaje ARP
	if(*ethSrcMac!=*arpSrcMac){
		printf("LOG:se ha detectado inconsistencia entre la MAC origen de la trama y la MAC origen del mensaje ARP\n");//podria ser proxyARP???
		printf("LOG:Son realmente distintos %s y %s  ??\n",ethSrcMac,arpSrcMac);
		//desde ya establezco que la trama es inconsistente en la direccion MAC de origen
		srcMacEquals=0;//ya que por default coinciden...
	}
	else{//nada... esta ok punto.
		printf("LOG:ethSrcMac=arpSrcMac     OK\n");
	}
	if(*ethDstMac!=*arpDstMac){
		printf("LOG: POR ENTRAR AQUI SE QUE SON MAC DESTINO DISTINTAS\n");
		//si difieren en la MAC destino pero es el caso particular del broadcast, entonces me aseguro!!
		printf("LOG:entonces %s es distinto de %s\n",ethDstMac,arpDstMac);
		//puts("siguio...\n");
		//printf("LOG:aaaaaaaaaaa tengo: %s y %s \n\n",ethDstMac,"ff:ff:ff:ff:ff:ff");
		if(*ethDstMac==*broadcastMac){
			dstBrdMacFlag=1;
			puts("LOG:ethDsrMac es broadcast!!!\n");
			//mmm iba al broadcast, sera una pregunta realmente? o sera para engañar?
			if(*arpDstMac==*zeroMac){//si es una pregunta ARP, lo marco para consultar su credibilidad? o consulto yo?
				//OK, es ARP request (al menos por la formacion)
				//es al menos una trama aceptable, podria verificarse luego pero al menos la acepto asi!
				//verifico si la IP de destino coincide con la del host que tiene la MAC ethDstMac
				//si quiero realmente probar esto, deberia chequear los pares MACIP de cada host participante
				dstZeroMacFlag=1;
				printf("LOG:puede que sea una pregunta ARP legitima..\n");//faltaria verificar match de ip-mac origen.
				//bien, esta trama esta marcada para verificarse integridad IP, luego steal en busqueda de spoofers
				doCheckIpI=1;
				doCheckSpoofer=1;
				nextState=1;
				type="PASS";
				printf("Finalizada la evaluacion, continua con la carga de datos...\n");
			}
			else{//Si entra aqui, es porque fue al broadcast, pero el ARP tiene un destino FIJO, es muy extraño!!
				printf("LOG:caso extraño, ethDstMac broadcast y arpDstMac Unicast...anomalo!!\n\n");
				//podria verificar el match IP-MAC origen, es un caso para WARN no para evaluarlo porque no viene al caso por ahora.
				//WARNING: deberia comprobarla completamente antes de informar..pero excede los limites del trabajo final
					//He decidido activar el flag type en WARN y no tratar el problema pero si mostrarlo!!
				
			}
		}
		else{//para los casos que no son broadcast en ethernet

			//destino ethernet bien definido, pero MAC destino en ARP DISTINA!!MALFORMACION!!
			//Este curioso caso se da por ejemplo con el DDwrt. el destino en ARP debera ser 0:0:0:0:0:0
			printf("LOG:antes de comparar con zero, tengo %s y %s\n",arpDstMac,zeroMac);
			if(*arpDstMac==*zeroMac){
				dstZeroMacFlag=1;
				//es altamente probable que sea una preguntita del AP que se hace el que no sabe quien es el cliente
				//para confirmar, valido ethSrcMac con arpSrcMac y luego arpSrcMac con arpSrcIp =)
				printf("LOG:Posible mensaje del AP, compruebe que ethSrcMac matchea con arpSrcIp para descartar ataque DoS\n");
				//tratar el error o escapar si OK
				//WARNING, marcar para comprobar y almacenar.
				//Escapa del formato de arpspoofing estudiado, me limito a mostrar el WARN, se descarta la trama
				type="WARN";
				nextState=0;
			}
			//el else de abajo OJO, porque queda el resto en el que las 4 mac son iguales!!
			else{//se trata de MACs destinos AMBIGUOS, es una trama anomala!! a no ser que sea del proxyARP
				printf("LOG:Trama con destino definido, revisando en profundidad....Posible ProxyARP\n\n");
				//No es el caso analizado, se descarta la trama pero se indica el WARN
				type="WARN";
				nextState=0;
				srcMacEquals=2;//por ser un caso anomalo de diferencia..
			}
		}
	}
	else{//macs destino coinciden, o sea bien dirigido..puede ser una trampa, si el origen tiene spoofeada la IP es la trama del atacante
		//o bien son tramas ARP que cayeron en el filtro (y vienen del portstealing) pero spoofeadas tambien por que no?
		//primero que nada chekeo si las MAC origen son iguales (primer verificacion, leo el resultado directamente)
			//si son iguales, veo el match MAC-IP del origen para ver si es ataque (consulto info real)
			switch(srcMacEquals){//lo puse en switch porque podria ser casos especiales de MAC Reservadas, 
						//de momento funciona igual q con IF-else
				case 1:
					//trama OK, debera verificar capa de red IP
						//si no matchea, entonces ALERTO EL ATAQUE!!!
						//SI MATCHEA, tenemos origen OK, destino OK.... nada raro.. me robe un ARP..
						printf("LOG:[Taxonomia de respuesta o ATAQUE], par[%s]-[%s]\n",ethDstMac,arpDstMac);
						//marcar para portstelear y GUARDAR el dialogo en la tabla
						doCheckIpI=1;//siempre primero, es la trivial.si conozco la info real, no noecesito el stealer.
						doCheckSpoofer=1;
						type="PASS";
						nextState=1;
						//Normalmente a no ser que sea una respuesta dirigida al sabueso, no veria estas tramas...
						//es por ello que lo mas seguro es que esta trama sean robadas del porstealing
				break;
				case 0:
						//no son iguales las MAC origen
						//Puede ser proxyARP????(ojo que esta filtrado) o bien 
							//el origen (sender) esta haciendo algo raro
						//WARNING-> inconsistencia en las MAC origen
						printf("LOG:macs origen no coinciden, posible proxyARP o trama anomala\n");
						type="WARN";
						nextState=2;
				break;
				default:
					printf("LOG:caso anomalo no tratado, no pudo determinarse igualdad de mac origen\n");
					//en estos casos, podria meter en la primer evaluacion respecto a las srcMac, numero superiores
					//para casos especiales, de momento no se trata este tipo de "mac reservada"
				break;
			}
	}
	
	//antes de ir a meterlo en la tabla, deberia comprobar que la informacion que estoy metiendo no existe ya de antes!!!


	//meter un lazo for como el siguiente para esta parte!!

	int dropFlag=0;
	int askFlag=0;

	for(i=1;i<100;i++){//ese tamaño de la tabla de memoria deberia ser un sizeof o de alguna manera conocerlo ahora hardcodeado

		printf("Revisor de tabla, pasada %d\n",i);

		//debera comparar con todas entradas en la tabla, si coinciden tengo un conocimento, descartar si es igual

		//comprobar si existe la entrada en la tabla (de cualquier sentido)
		
		//pero si la entrada en la tabla esta para descartar o para usar entonces saltar el CICLO ACTUAL
		/*
		if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).hit==(3|4)){
			//saltar ciclo
			printf("saltando esta entrada de la tabla por no ser conocimiento...\n");
			continue;
		}
		*/
		//evaluo primero los casos especiales de broadcast
		if(dstBrdMacFlag==1){
			//este caso es especial, es una pregunta al broadcast
			//estos son los que me interesan porque me dice quien esta interesado en hablar con quien:
			
			if(dstZeroMacFlag==1){
				printf("Tenemos una pregunta ARP aparentemente, entonces el pregunton es posible victima a futuro\n");
				dropFlag=0;
				askFlag=1;
				//break;//continue;
			}
		}
		else{
			if(dstZeroMacFlag==1){
				printf("tratar este caso (descartando ahora).. es mensaje del AP o destino ARP 0.0.0.0 sin brd en eth\n");
				dropFlag=1;
				break;//continue;
			}
		}
		int comparacion=69;
		if(askFlag==1){
			//si es una pregunta, me fijo si el pregunton esta en la tabla junto a su destino
			printf("se va a comparar : %s con %s\n",( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).ethSrcMac ),ethSrcMac );
			if(  ((((arpDTMWorker_arguments *) arguments)->shmPtr[i]).ethSrcMac) != NULL){
				printf("no nulo\n");
				comparacion=strncmp( ((((arpDTMWorker_arguments *) arguments)->shmPtr[i]).ethSrcMac), ethSrcMac, (int) strlen(ethSrcMac));
				printf("valor de la comparacion = %d\n",comparacion);
				if(comparacion == 0){
					printf("eran iguales entonces por el strlen\n");
				}
				else{
					printf("eran DISTINTOS por el strlen\n");
				}
			}
			else{
				//si esta nula la entrada, saltarla y ahorrar tiempo!!
				continue;//salta con este?
				printf("era nulo....\n");
			}
			if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).ethSrcMac==ethSrcMac){
				printf("este pregunton ya pregunto antes, a ver si es el mismo destino...\n");
				if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).arpDstIp==arpDstIp){
					printf("es el mismo destino, a ver si no esta spoofeada la pregunta...\n");
					//ahora puedo hacer una busqueda en la tabla..si coincide que la ip es distinta entonces
					//se que estamos frente a una pregunta spoofeada
					if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).arpSrcIp==arpSrcIp){
						//si entra aca significa que coincidio origen, destino y las IP origen
						printf("esta entrada ya existia en la tabla, la descartamos...\n");
						dropFlag=1;//descartar...
						//incremento el hit de la entrada.
						//bloquear entrada...
						sem_wait( & ((((arpDTMWorker_arguments *) arguments)->shmPtr[i]).semaforo) );
						//usar la entrada de la tabla
						//Si estaba para eliminar, le cambio el nextState
						if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).nextState==(3||4)){
							printf("Esta entrada se iba a eliminar...\n");
							(((arpDTMWorker_arguments *) arguments)->shmPtr[i]).nextState=1;
						}
						//aumento el hit
						(((arpDTMWorker_arguments *) arguments)->shmPtr[i]).hit++;
						//liberar entrada de la tabla
						sem_post( & ((((arpDTMWorker_arguments *) arguments)->shmPtr[i]).semaforo) );
						//ahora corto porque solo queria aumentar el HIT
						break;
					}
					else{
						printf("se encontro la entrada, pero difieren IP origen, posible pregunta spoofed\n");
						dropFlag=0;//corresponde.... por mas que venga de antes en 0
						doCheckSpoofer=1;//sip.. si hay inconsistencia hay algo raro..
					}
				}
			}
		}
















		//printf("Estado de la entrada n°%d: %d\n", i,(((arpDTMWorker_arguments *) arguments)->shmPtr[i]).hit  );
		//Comparo las ethSrcMac de la tabla con las MAC que tengo en este hilo
		printf("mostrando comparacion: %s con %s \n",(((arpDTMWorker_arguments *) arguments)->shmPtr[i]).ethSrcMac,ethSrcMac);
		if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).ethSrcMac==ethSrcMac){
			printf("Coincidencia de ethSrcMac_en_tabla con ethSrcMac\n");
			//comprobar si el otro participande del dialogo es el de ahora:
			if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).ethDstMac==ethDstMac){
				printf("coinsidencia de dialogo!! tambien coincidieron las mac destino\n");
				//comprobar integridad IP:
				if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).arpSrcIp==arpSrcIp){
					printf("IP src OK\n");
					if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).arpDstIp==arpDstIp){
						printf("IP destino OK, entrada REPETIDA EN LA TABLA\n");
						dropFlag=1;
					}
					else{
						printf("conflicto: La IP destino actual no coincide con la almacenada posible spoofing\n");
						//marcar de algun modo el conflicto!!! (podria ser el hit???)
						dropFlag=0;
					}
				}
				else{
					//IP origen de ahora no coincide con el origen de la entrada almacenada
					printf("IP origen en discordia con la entrada almacenada\n");
					//deberia marcarla para revisar, entonces se almacena
					dropFlag=0;
				}
			}
			else{
				//no seria la misma trama porque tienen mismo origen pero distinto destino en MAC
				dropFlag=0;
			}
		}
		else{
			if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).ethSrcMac==ethDstMac){
	                        printf("Coincidencia de ethDstMac_en_tabla con ethSrcMac\n");
        	                //comprobar si el otro participande del dialogo es el de ahora:
				if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).ethDstMac==ethSrcMac){
					printf("coinsidencia de dialogo pero cruzado!!\n");
					//comprobar integridad IP:
					if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).arpSrcIp==arpDstIp){
						//macs iguales aunque cruzadas:

						printf("IP src y dst cruzadas OK\n");
						if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).arpDstIp==arpSrcIp){
							printf("IP destino OK, entrada REPETIDA EN LA TABLA (CRUZADA)\n");
							dropFlag=1;
						}
						else{
							printf("conflicto: IP dest. actual no coincide con la almacenada posible spoofing\n");
							//marcar de algun modo el conflicto!!! (podria ser el hit???)
							dropFlag=0;
						}
					}
					else{
						//IP origen de ahora no coincide con el origen de la entrada almacenada
						printf("IP origen (CRUZADA) en discordia con la entrada almacenada\n");
						//deberia marcarla para revisar, entonces se almacena
						dropFlag=0;
					}
				}
				else{
					//no seria la misma trama porque tienen mismo origen pero distinto destino en MAC
					dropFlag=0;
				}
			}
		}//else if
		//ahora si esta dropFlag arriba, entonces corto el lazo y termino descartando la trama
		if(dropFlag==1){
			printf("LOG: se desacarta la trama (quiza por coincidir en la tabla)\n");
			return 0;
		}		
	}//lazo FOR
	//facil, si esta activo el DROP, pues finalizar, sino continuar ejecucion
	if(dropFlag==1){
		printf("LOG: se desacarta la trama (quizaa por coincidir en la tabla)\n");
		return 0;
	}


	//Bueno, en general me voy a interesar en los casos LEGITIMOS y en los casos con Taxonomia de ATAQUE, luego vere que hago con los otros
	
	//tomar una entrada de la tabla para guardar los datos:

	int insertFlag=0;
	int whiler=0;
	//while(whiler<1000){while ++;sleep(whiler);//para que mantenga la intencion de almacenar aunque este lleno y espere mas cda vez..

	for(i=1;i<100;i++){//ese tamaño de la tabla de memoria deberia ser un sizeof o de alguna manera conocerlo ahora hardcodeado
		printf("dentro antes del for...\n");
		printf("Estado de la entrada n°%d: %d\n", i,(((arpDTMWorker_arguments *) arguments)->shmPtr[i]).hit  );
		if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).nextState==4){
			printf("entrada en la tabla n° %d esta disponible para uso\n",i);
			//Obtener acceso exclusivo en la entrada de la tabla
			//sem_wait((sem_t *) & (shmPtr[i].semaforo));
			sem_wait( & ((((arpDTMWorker_arguments *) arguments)->shmPtr[i]).semaforo) );
			//usar la entrada de la tabla
			//vuelvo a comprobar, por las dudas de haberme encolado y haber sido utilizada la entrada antes de mi turno
			if( (((arpDTMWorker_arguments *) arguments)->shmPtr[i]).nextState!=4){
				printf("la entrada fue utilizada, continuar busqueda...\n");
				//desbloquearla antes de soltar:
				sem_post( & ((((arpDTMWorker_arguments *) arguments)->shmPtr[i]).semaforo) );
				break;
			}
			//else...continua sin mas

			//aca quiero pasarle la cadena que esta con los punteros locales a la estructura, pero que cuando muera
			// el hilo, no me de segmentation fault!!! ajajaj consultar esta parte.

			(((arpDTMWorker_arguments *) arguments)->shmPtr[i]).ethSrcMac=ethSrcMac;
			(((arpDTMWorker_arguments *) arguments)->shmPtr[i]).ethDstMac=ethDstMac;
			(((arpDTMWorker_arguments *) arguments)->shmPtr[i]).arpSrcMac=arpSrcMac;
			(((arpDTMWorker_arguments *) arguments)->shmPtr[i]).arpDstMac=arpDstMac;
			(((arpDTMWorker_arguments *) arguments)->shmPtr[i]).arpSrcIp=arpSrcIp;
			(((arpDTMWorker_arguments *) arguments)->shmPtr[i]).arpDstIp=arpDstIp;
			//informacion de estado:
			(((arpDTMWorker_arguments *) arguments)->shmPtr[i]).doCheckIpI=doCheckIpI;
			(((arpDTMWorker_arguments *) arguments)->shmPtr[i]).doCheckSpoofer=doCheckSpoofer;
			(((arpDTMWorker_arguments *) arguments)->shmPtr[i]).nextState=nextState;
			(((arpDTMWorker_arguments *) arguments)->shmPtr[i]).type=type;
			//segun el caso, setear el hit:
			(((arpDTMWorker_arguments *) arguments)->shmPtr[i]).hit++;
			//Liberar la entrada de la tabla:
			sem_post( & ((((arpDTMWorker_arguments *) arguments)->shmPtr[i]).semaforo) );
			insertFlag=1;
			break;//;) por eso corta y funciona el printf siguiente cuando no.. 
		}
		printf("La %d entrada en la tabla no esta disponible\n",i);
	}
	//una vez almacenada... termino la vida de este Worker =)

	printf("sale del for\n");
	if(insertFlag==0){
		printf("No ha sido posible cargar la nueva entrada en la tabla, es probable que este LLENA!!! \n");
	}
	else{
		printf("se inserto la entrada en la tabla\n");
	}


	return 0;
}
