/// This is an example program from the website www.microhowto.info
// © 2012 Graham Shaw
// Copying and distribution of this software, with or without modification,
// is permitted in any medium without royalty.
// This software is offered as-is, without any warranty.

// Purpose: to construct an ARP request and write it to an Ethernet interface
// using libpcap.
//
// See: "Send an arbitrary Ethernet frame using libpcap"
// http://www.microhowto.info/howto/send_an_arbitrary_ethernet_frame_using_libpcap.html

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/if_ether.h>
#include <sys/ioctl.h>

//MENSAJES
#define MSG_SHOW_PARAMS "Parametros recibidos :\n"
//ERRORES
#define ERR_PARAM_IP "La direccion IP no es valida. Revisar formato\n"
#define ERR_PARAM_IFLONG "El nombre de la interfaz es muy largo\n"



int arper(char* mac2guard, const char* if_name, const char* target_ip_string){

write(1,MSG_SHOW_PARAMS,sizeof(MSG_SHOW_PARAMS));
write(1,if_name,(int)strlen(if_name));
write(1,"\n",(int)strlen("\n"));
//write(1,mac2guard,(int)strlen(mac2guard));
write(1,"\n",(int)strlen("\n"));

//printf("\nholaaa aqui el arper con: \n MAC: %s \nplaca: %s\nIP: %s\n",mac2guard,if_name,target_ip_string);

    // Construct Ethernet header (except for source MAC address).
    // (Destination set to broadcast address, FF:FF:FF:FF:FF:FF.)
	//estructura para cabecera ethernet
    struct ether_header header;
	//tipo de direccion
    header.ether_type=htons(ETH_P_ARP);
	//Setear direccion MAC de DESTINO. Podria luego ver de enviar algunos UNICAST (conociendo la MAC destino)
    memset(header.ether_dhost,0xff,sizeof(header.ether_dhost));
//SETEO mac origen (0xff para broadcast).
//	memset(header.ether_shost,0xff,sizeof(header.ether_shost));

    // Construct ARP request (except for MAC and IP addresses).
    struct ether_arp req;
    req.arp_hrd=htons(ARPHRD_ETHER);
    req.arp_pro=htons(ETH_P_IP);
    req.arp_hln=ETHER_ADDR_LEN;
    req.arp_pln=sizeof(in_addr_t);
    req.arp_op=htons(ARPOP_REQUEST);
    memset(&req.arp_tha,0,sizeof(req.arp_tha));

    // Convert target IP address from string, copy into ARP request.
    struct in_addr target_ip_addr={0};
    if (!inet_aton(target_ip_string,&target_ip_addr)) {
//       fprintf(stderr,"%s is not a valid IP address",target_ip_string);
       write(1,ERR_PARAM_IP,sizeof(ERR_PARAM_IP));
       exit(1);
    }
    memcpy(&req.arp_tpa,&target_ip_addr.s_addr,sizeof(req.arp_tpa));


	//Aunque puede parecer tonto.. lo dejo porque no se como determina QUE placa usar todabia...la MAC se la voy a poner igual luego por argumento
    // Write the interface name to an ifreq structure,
    // for obtaining the source MAC and IP addresses.
    struct ifreq ifr;
    size_t if_name_len=strlen(if_name);
    if (if_name_len<sizeof(ifr.ifr_name)) {
        memcpy(ifr.ifr_name,if_name,if_name_len);
        ifr.ifr_name[if_name_len]=0;
    } else {
	write(1,ERR_PARAM_IFLONG,sizeof(ERR_PARAM_IFLONG));
	//        fprintf(stderr,"interface name is too long");
        exit(1);
    }
    // Open an IPv4-family socket for use when calling ioctl.
    int fd=socket(AF_INET,SOCK_DGRAM,0);
    if (fd==-1) {
        perror(0);
        exit(1);
    }

	//ESTA SERIA MI IP... LO DEJO..OJO que me parece que se vale de la NIC que recibio por argumento!!
    // Obtain the source IP address, copy into ARP request
    if (ioctl(fd,SIOCGIFADDR,&ifr)==-1) {
        perror(0);
        close(fd);
        exit(1);
    }
    struct sockaddr_in* source_ip_addr = (struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(&req.arp_spa,&source_ip_addr->sin_addr.s_addr,sizeof(req.arp_spa));

	//NO, LA MAC ORIGEN LA SETEO POR ARGUMENTO =) mac2guard
    // Obtain the source MAC address, copy into Ethernet header and ARP request.
    if (ioctl(fd,SIOCGIFHWADDR,&ifr)==-1) {
        perror(0);
        close(fd);
        exit(1);
    }


    if (ifr.ifr_hwaddr.sa_family!=ARPHRD_ETHER) {
        fprintf(stderr,"not an Ethernet interface");
        close(fd);
        exit(1);
    }
	//Setear MAC origen=!=!=!=????
//	ifr.ifr_hwaddr.sa_data[0]=0x12;

//convierto mac2guard al formato hex

//SSSSSSSSSSSSSSSSSSSSS

//char cadena[] = "Este es un enunciado con 7 tokens";
char cadena[17];
char *mac_parts[6];
int cont=0;
strcpy(cadena,&mac2guard[0]);//meto el char* en un array

char *ptrToken; /* crea un apuntador char */
   
printf( "%s\n%s\n\n%s\n",      "La cadena a dividir en tokens es:", cadena, 
      "Los tokens son:" );
          
ptrToken = strtok( cadena, "-" ); /* comienza la divisiÃƒÂ³n en tokens del enunciado */
    /* continua la divisiÃƒÂ³n en tokens hasta que ptrToken se hace NULL */
cont=0;
while ( ptrToken != NULL ) { 
	printf( "%s\n", ptrToken );
	mac_parts[cont]=ptrToken;
	cont++;
	ptrToken = strtok( NULL, "-" ); /* obtiene el siguiente token */
} /* fin de while */ 

//ssssssssssssssssssssss
printf("holaaaaaaaaaaaaaaaaaaaaa\n");
int mac_byte;
unsigned char byte;
unsigned char value;
int i;
//ahora un lazo for para cargar las partes de la mac en la estuctura ether

for(i=0;i<6;i++){
	sscanf(mac_parts[i],"%x",&mac_byte);
	byte = mac_byte & 0xFF;
	printf("que paso: %x\n",byte);
	value=byte;
	ifr.ifr_hwaddr.sa_data[i]=value;
}

/*


ifr.ifr_hwaddr.sa_data[1]=0xff;
ifr.ifr_hwaddr.sa_data[2]=value;
ifr.ifr_hwaddr.sa_data[3]=0x78;
ifr.ifr_hwaddr.sa_data[4]=0x9f;
ifr.ifr_hwaddr.sa_data[5]=0x12;
*/

    const unsigned char* source_mac_addr=(unsigned char*)ifr.ifr_hwaddr.sa_data;

//	printf("mac source: %X \n\n",*source_mac_addr);

//aca abajo es evidente que intenta setear la mac obtenida en la linea anterior, pero yo ya he seteado al principio la MAC por agumento =)
    memcpy(header.ether_shost,source_mac_addr,sizeof(header.ether_shost));
    memcpy(&req.arp_sha,source_mac_addr,sizeof(req.arp_sha));
    close(fd);

    // Combine the Ethernet header and ARP request into a contiguous block.
    unsigned char frame[sizeof(struct ether_header)+sizeof(struct ether_arp)];
    memcpy(frame,&header,sizeof(struct ether_header));
    memcpy(frame+sizeof(struct ether_header),&req,sizeof(struct ether_arp));

    // Open a PCAP packet capture descriptor for the specified interface.
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_errbuf[0]='\0';
    pcap_t* pcap=pcap_open_live(if_name,96,0,0,pcap_errbuf);
    if (pcap_errbuf[0]!='\0') {
        fprintf(stderr,"%s\n",pcap_errbuf);
    }
    if (!pcap) {
        exit(1);
    }

    // Write the Ethernet frame to the interface.
    if (pcap_inject(pcap,frame,sizeof(frame))==-1) {
        pcap_perror(pcap,0);
        pcap_close(pcap);
        exit(1);
    }

    // Close the PCAP descriptor.
    pcap_close(pcap);

	puts("Fin del arper\n");
    return 0;
}
