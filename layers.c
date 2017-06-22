#include <sys/socket.h>
#include <features.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/udp.h>


int createRawSocket(int protocolToSniff);
int bindRawSocketToInterface(const char *device, int rawSocket, int protocol);
unsigned char *printPacketInHex(int length, unsigned char *p);
unsigned char *printEthernetHeader(int length, unsigned char *p);
unsigned char *printIpHeader(int length, unsigned char *p, int *tcpOrUdp);
unsigned char *processTcpUdpHeader(int length, unsigned char *p, int tcpOrUdp);
unsigned char *printTcpHeader(int length, unsigned char *p);
unsigned char *printUdpHeader(int length, unsigned char *p);


int main(void){
    
    printf("\nPROGRAM START\n----------------------------------------------\n\n\n");
    
    int rawSocket;                              // Socket descriptor 
    unsigned char packetBuffer[2048];           // Will contain packets sent to us
    int length;                                 // Length of packet
    int numPacketsToSniff;                      // User input for number of packets to sniff
    struct sockaddr_ll packetInfo;              // structure with info about the packet
    int packetInfoSize = sizeof(packetInfo);
    
    //Pointers to headers: Sequence(size): ETH(14) -> IP(20) -> TCP(20)/UDP(8) -> DATA
    unsigned char *EthernetHeader = packetBuffer;
    unsigned char *ipHeader;
    int tcpOrUdp = -1;                          // To check protocol type; TCP/UDP
    unsigned char *tcpUdpHeader;
    unsigned char *DATA;
    
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
    for(int i = 0; i < numPacketsToSniff ; i++){
        
        printf("\nPrinting packet: %d\n\n", i+1);
        length = recvfrom(rawSocket, packetBuffer, 2048, 0,(struct sockaddr*)&packetInfo, &packetInfoSize);
        if(length == -1){
            printf("Receive-from returned -1 \n");
            exit(-1);
        }
        else{
            unsigned char *p = packetBuffer;            // p = Pointer to first instance of Buffer
            printf("The entire Packet: \n");
            p = printPacketInHex(length, p);
            
            // Resetting the pointer to the packetBuffer
            // "p" WILL TRACK THE POSITION IN THE BUFFER THROUGH THE ENTIRE PROCESS
            p = packetBuffer;
            
            // Printing Ethernet Header and getting pointer to IP header
            ipHeader = printEthernetHeader(length, p);
            
            // Printing IP Header and getting pointer to TCP/UDP header
            tcpUdpHeader = printIpHeader(length, ipHeader, &tcpOrUdp);
            
            // Process and Print TCP or UDP header and getting a pointer to DATA
            DATA = processTcpUdpHeader(length, p, tcpOrUdp);
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
unsigned char* printPacketInHex( int length, unsigned char *p){
    
    for(int i = 0; i < length; i++){
        printf("%0.2x ", *p);
        p++;
    }
    printf("\n");
    return (p);
}
unsigned char *printEthernetHeader(int length, unsigned char *p){
    
    if (length > sizeof(struct ethhdr)){
        struct ethhdr *etherHeader = (struct ethhdr *)p;  // ETH header size = 14
        
        printf("\n\nEthernet Header:\n");
        
        // Destination Mac Printing: First 6 bytes
        printf("\tDestination MAC: ");
        p = printPacketInHex(sizeof(etherHeader->h_dest), p);
        
        // Source Mac Printing: Next 6 bytes
        printf("\tSource MAC: ");
        p = printPacketInHex(sizeof(etherHeader->h_source), p);
        
        // Protocol type Printing: Next 2 bytes
        printf("\tProtocol, Packet type ID: ");
        p = printPacketInHex(sizeof(etherHeader->h_proto), p);
        
        if(ntohs(etherHeader->h_proto) == ETH_P_IP){
            // Returning pointer to IP-header 
            return(p);
        }
        else{
            printf("\n\nThe packet is not an IP-Packet \n");
            exit(-1);
        }    
    }    
}
unsigned char *printIpHeader(int length, unsigned char *p, int *tcpOrUdp){
    
    if(length >= (sizeof(struct ethhdr) + sizeof(struct iphdr))){
        struct iphdr *ipHeader = (struct iphdr *)p;
        
        // Using Structure sockaddr_in . sin_add . s_addr to store IP addresses
        // IF NEEDED IN FUTURE MAKE THE BELOW GLOBAL
        
        struct sockaddr_in source, dest;
        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = ipHeader->saddr;
        memset(&dest,0, sizeof(dest));
        dest.sin_addr.s_addr = ipHeader->daddr;
        
        printf("\n\nIP Header:\n");
        
        // Printing source and destination IP address
        printf("\tDestination IP: %s\n", inet_ntoa(dest.sin_addr));
        printf("\tSource IP: %s\n", inet_ntoa(source.sin_addr));
        
        // Printing other Details
        printf("\n\tIP version: %d\n", (int)ipHeader->version);
        printf("\tChecksum: %d\n", (int)ipHeader->check);
        printf("\tProtocol: %d\n", (int)ipHeader->protocol);
        printf("\tTTL: %d\n", (int)ipHeader->ttl );
        printf("\tType of Service: %d\n", (int)ipHeader->tos);
        printf("\tIP Total Length: %d\n", (int)ipHeader->tot_len);
        printf("\tIP Header Length: %d\n", (int)ipHeader->ihl);
        printf("\tIdentification: %d\n", (int)ipHeader->id);
             
        
        // To find out if the protocol is TCP or UDP sending back protocol #
        *tcpOrUdp = ipHeader->protocol;
                   
        return(p + sizeof(struct iphdr)); // IP header size = 20  
    }
}
unsigned char *processTcpUdpHeader(int length, unsigned char *p, int tcpOrUdp){
    if(tcpOrUdp == IPPROTO_TCP){      // IPPROTO_TCP = 6 , IPPROTO_IP = 0
        p = printTcpHeader(length, p);
        printf("\n\n Protocol in use : TCP");
        return(p);
    }
    else if(tcpOrUdp == IPPROTO_UDP){ // IPPROTO_UDP = 17
        p = printUdpHeader(length, p);
        printf("\n\n Protocol in use : UDP");
        return(p);
    }
    else{
        printf("\n Protocol in use is Neither TCP or UDP \n");
        exit(-1);
    }
}
unsigned char *printTcpHeader(int length, unsigned char *p){
    if(length >= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))){
        struct tcphdr *tcpHeader = (struct tcphdr *)p;
        
        printf("\n\nTCP Header:\n");
        
        // Printing source and destination Port # and seq and ack #
        printf("\tDestination Port: %d\n", (int)ntohs(tcpHeader->dest));
        printf("\tSource Port: %d\n", (int)ntohs(tcpHeader->source));
        printf("\tSequence Number: %d\n", (int)ntohs(tcpHeader->seq));
        printf("\tAcknowledgment Number: %d\n", (int)ntohs(tcpHeader->ack_seq));
        
        // Printing rest of details
        printf("\n\tHeader Length: %d\n", (int)tcpHeader->doff);
        printf("\tCWR Flag: %d\n", (int)tcpHeader->cwr);
        printf("\tECN Flag: %d\n", (int)tcpHeader->ece);
        printf("\tUrgent Flag: %d\n", (int)tcpHeader->urg);     
        printf("\tAcknowledgment Flag: %d\n", (int)tcpHeader->ack);
        printf("\tPush Flag: %d\n", (int)tcpHeader->psh);
        printf("\tReset Flag: %d\n", (int)tcpHeader->rst);
        printf("\tSynchronize Flag: %d\n", (int)tcpHeader->syn);
        printf("\tFinish Flag: %d\n", (int)tcpHeader->fin);
        printf("\tWindow: %d\n", (int)ntohs(tcpHeader->window));
        printf("\tChecksum: %d\n", (int)ntohs(tcpHeader->check));
        printf("\tUrgent Pointer: %d\n", (int)tcpHeader->urg_ptr);              
    }       
    // Size of TCP header = 20
    return(p + sizeof(struct tcphdr));   
    
}
unsigned char *printUdpHeader(int length, unsigned char *p){
    if(length >= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))){
        struct udphdr *udpHeader = (struct udphdr *)p;
        
        printf("\n\nUDP Header:\n");
        
        // Printing source and destination Port # and seq and ack #
        printf("\tDestination Port: %d\n", (int)ntohs(udpHeader->dest));
        printf("\tSource Port: %d\n", (int)ntohs(udpHeader->source));
        printf("\n\tUDP Length: %d\n", (int)ntohs(udpHeader->len));
        printf("\tChecksum: %d\n", (int)ntohs(udpHeader->check));
     
        // Size of UDP header = 8
        return(p + sizeof(struct udphdr));       
    }    
}