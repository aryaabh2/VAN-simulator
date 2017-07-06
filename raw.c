#include <sys/socket.h>
#include <features.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/if.h>
//#include <net/if.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


int createRawSocket(int protocolToSniff);
int bindRawSocketToInterface(const char *device, int rawSocket, int protocol);
void printPacketInHex(int length, unsigned char *p);

int main(void){
    
    printf("\nPROGRAM START\n----------------------------------------------\n\n\n");
    
    int rawSocket;                              // Socket descriptor 
    unsigned char packetBuffer[2048];           // Will contain packets sent to us
    int length;                                 // Length of packet
    int numPacketsToSniff;                      // User input for number of packets to sniff
    struct sockaddr_ll packetInfo;              // structure with info about the packet
    int packetInfoSize = sizeof(packetInfo);
    
    // Creating Raw Socket
    printf("Creating Raw socket\n");
    rawSocket = createRawSocket(ETH_P_IP);
    
    // Getting number of packets to sniff
    printf("Enter Number of Packets to sniff:");
    scanf(" %d", &numPacketsToSniff);
    printf("Number of Packets to sniff: %d\n\n", numPacketsToSniff);
  
    // Binding to interface
    int a = bindRawSocketToInterface("eth0", rawSocket, ETH_P_IP);
    printf("managed to exit bind function if 1 = %d\n",a);
    
    // Start Sniffing
    int i = 0;
    for(i = 0; i < numPacketsToSniff ; i++){
        
        printf("Printing packet: %d\n", i+1);
        length = recvfrom(rawSocket, packetBuffer, 2048, 0,(struct sockaddr*)&packetInfo, &packetInfoSize);
        if(length == -1){
            printf("Receive-from returned -1 \n");
            exit(-1);
        }
        else{
            unsigned char *p = packetBuffer;            // Pointer to first instance of Buffer
            printf("The entire Packet: \n");
            printPacketInHex(length, p);
            
            // Resetting the pointer to the packetBuffer
            p=packetBuffer;
            
            
        }
    }
       
    printf("\n\n----------------------------------------------\nPROGRAM END\n\n");
    return (EXIT_SUCCESS);
}

int createRawSocket(int protocolToSniff){
    
    int rawSocket = socket(PF_PACKET, SOCK_RAW, htons(protocolToSniff));
    
    // Socket() returns -1 if unable to create socket
    if(rawSocket == -1){
        printf("Error in Socket Creation. %d\n\n", errno);
        exit(-1);
    }
    else{
        printf("Socket created: rawSocket = %d \n\n", rawSocket);
        return (rawSocket);
    }    
}
int bindRawSocketToInterface(const char *device, int rawSocket, int protocol){
    struct sockaddr_ll sll;
    struct ifreq ifr;  //interface request structure
    
    // first need to get the Interface index: number which kernel uses to identify interfaces
    
    strncpy(ifr.ifr_name, device, IFNAMSIZ);
    
    ioctl(rawSocket, SIOCGIFINDEX, &ifr);
    
    if((ioctl(rawSocket, SIOCGIFINDEX, &ifr)) == -1){     // IO control
        printf("Error in getting Interface Index \n");
        exit(-1);
    }
    else{
        printf("Interface name = %c%c%c%c\n", ifr.ifr_name[0],ifr.ifr_name[1],ifr.ifr_name[2],ifr.ifr_name[3]);
        printf("Binding new socket to this interface index we just got.\n");
        sll.sll_family = AF_PACKET;
        sll.sll_ifindex = ifr.ifr_ifindex;
        sll.sll_protocol = htons(protocol);
        
        bind(rawSocket, (struct sockaddr *)&sll, sizeof(sll));
        
        if( bind(rawSocket, (struct sockaddr *)&sll, sizeof(sll)) == -1 ){
            printf("Error Binding Raw socket to interface \n");
            exit(-1);
        }
        else{
            printf("Socket bound to the interface %c%c%c%c\n\n", ifr.ifr_name[0],ifr.ifr_name[1],ifr.ifr_name[2],ifr.ifr_name[3]);
            return (1);
        }
    }    
}

void printPacketInHex( int length, unsigned char *p){
    
    printf("\n\n _________ PACKET___START ________\n\n");
    
    int i = 0;
    for(i = 0; i < length; i++){
        printf("%x ", *p);
        p++;
    }
    printf("\n\n _________ PACKET___END __________\n\n");
}
