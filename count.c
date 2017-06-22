// Include files for raw sockets and layers
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
#include <stdbool.h>
#include <linux/ip.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <linux/udp.h>

// Include files for counter
#include <time.h>
#include <unistd.h>


typedef struct packetAddresses{
    char destIP[16];
    char sourceIP[16];
    int destPort;
    int sourcePort;  
    
    char destMAC[7];
    char sourceMAC[7];
    
    int numPackets;
}address;

int createRawSocket(int protocolToSniff);
int bindRawSocketToInterface(const char *device, int rawSocket, int protocol);
unsigned char *printPacketInHex(int length, unsigned char *p);
unsigned char *printEthernetHeader(int length, unsigned char *p, address *temp);
unsigned char *printIpHeader(int length, unsigned char *p, int *tcpOrUdp, address *temp);
unsigned char *processTcpUdpHeader(int length, unsigned char *p, int tcpOrUdp, address *temp);
unsigned char *printTcpHeader(int length, unsigned char *p, address *temp);
unsigned char *printUdpHeader(int length, unsigned char *p, address *temp);
void arrangeFlows(address *flows, address temp);
void printFlows(address *flows);

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
    
    //Array of structures to count flows
    address flows[200];
    address temp;
    temp.numPackets = 0;                        // Setting number of packets to 0 in start
    flows[0].destPort = 0;                      // Setting ip and port to 0 to know where to add new packets
    flows[0].sourcePort = 0;
    flows[0].destIP[0] = '\0';
    flows[0].sourceIP[0] = '\0'; 
    
    
    // Creating Raw Socket
    printf("Creating Raw socket\n");
    rawSocket = createRawSocket(ETH_P_IP);
      
    // Binding to interface
    bindRawSocketToInterface("eth0", rawSocket, ETH_P_IP);
    
    // Start Sniffing
    struct timespec startTime, runTime, currentTime;
    
    printf("Enter the time to run the program for:\n");
    printf("Seconds:\n");
    scanf(" %d", &runTime.tv_sec);
    printf("NANO-Seconds:\n");
    scanf(" %d", &runTime.tv_nsec);
   
    clock_gettime(CLOCK_REALTIME, &startTime);
    clock_gettime(CLOCK_REALTIME, &currentTime);
    int i = 0;
    while(((currentTime.tv_sec - startTime.tv_sec) < runTime.tv_sec) || (((currentTime.tv_sec - startTime.tv_sec) == runTime.tv_sec && (currentTime.tv_nsec - startTime.tv_nsec) <= runTime.tv_nsec))){
        
        //printf("\n\nPrinting packet: %d\n", i+1);
        length = recvfrom(rawSocket, packetBuffer, 2048, 0,(struct sockaddr*)&packetInfo, &packetInfoSize);
        if(length == -1){
            printf("Receive-from returned -1 \n");
            exit(-1);
        }
        else{
            unsigned char *p = packetBuffer;            // p = Pointer to first instance of Buffer
            
           // Printing Ethernet Header and getting pointer to IP header
            ipHeader = printEthernetHeader(length, p, &temp);
            
            printf("\nDestination MAC: ");
            printPacketInHex(6, temp.destMAC);
            printf("Source MAC: ");
            printPacketInHex(6, temp.sourceMAC);  
           
            
            // Printing IP Header and getting pointer to TCP/UDP header
            tcpUdpHeader = printIpHeader(length, ipHeader, &tcpOrUdp, &temp);
            printf("Destination IP: %s\n", temp.destIP);
            printf("Source IP: %s\n", temp.sourceIP);
            
            // Process and Print TCP or UDP header and getting a pointer to DATA
            processTcpUdpHeader(length, p, tcpOrUdp, &temp);
            printf("Destination Port: %d \n", temp.destPort);
            printf("Source Port: %d \n", temp.sourcePort);
          
            //printFlows(&temp);
            //Function to count flows
            arrangeFlows(flows, temp);
        }
        clock_gettime(CLOCK_REALTIME, &currentTime);
        i++;
    }
    
    printf("\n\nTotal packets printed: %d", i);
    
    printf("\n\nPrinting all the flows: \n");
    
    printFlows(flows);
    
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
    
    int i;
    for(i= 0; i < length; i++){
        printf("%0.2x ", *p);
        p++;
    }
    printf("\n");
    return (p);
}
unsigned char *printEthernetHeader(int length, unsigned char *p,address *temp){
    
    if (length > sizeof(struct ethhdr)){
        struct ethhdr *etherHeader = (struct ethhdr *)p;  // ETH header size = 14
        
        //printf("Ethernet Header:\n");
       
        // Destination Mac Saving: First 6 bytes
        int i;
        for(i= 0; i < sizeof(etherHeader->h_dest); i++){
            temp->destMAC[i] = *p;
            p++;
        }
               
        // Source Mac Saving: Next 6 bytes
        for(i= 0; i < sizeof(etherHeader->h_source); i++){
            temp->sourceMAC[i] = *p;
            p++;
        }
        
        
        if(ntohs(etherHeader->h_proto) == ETH_P_IP){
            // Returning pointer to IP-header 
            return(p + 2);
        }
        else{
            printf("\n\nThe packet is not an IP-Packet \n");
            exit(-1);
        }    
    }    
}
unsigned char *printIpHeader(int length, unsigned char *p, int *tcpOrUdp, address *temp){
    
    if(length >= (sizeof(struct ethhdr) + sizeof(struct iphdr))){
        struct iphdr *ipHeader = (struct iphdr *)p;
        
        // Using Structure sockaddr_in . sin_add . s_addr to store IP addresses
        // IF NEEDED IN FUTURE MAKE THE BELOW GLOBAL
        
        struct sockaddr_in source, dest;
        memset(&source, 0, sizeof(source));
        source.sin_addr.s_addr = ipHeader->saddr;
        memset(&dest,0, sizeof(dest));
        dest.sin_addr.s_addr = ipHeader->daddr;
        
        //printf("\n\nIP Header:\n");
        
        // Saving source and destination IP address
        strcpy(temp->destIP, inet_ntoa(dest.sin_addr));
        strcpy(temp->sourceIP, inet_ntoa(source.sin_addr));   
        
        // To find out if the protocol is TCP or UDP sending back protocol #
        *tcpOrUdp = ipHeader->protocol;
                   
        return(p + sizeof(struct iphdr)); // IP header size = 20  
    }
}
unsigned char *processTcpUdpHeader(int length, unsigned char *p, int tcpOrUdp, address *temp){
    if(tcpOrUdp == IPPROTO_TCP){      // IPPROTO_TCP = 6 , IPPROTO_IP = 0
        p = printTcpHeader(length, p, temp);
        //printf("\n\n Protocol in use : TCP");
        return(p);
    }
    else if(tcpOrUdp == IPPROTO_UDP){ // IPPROTO_UDP = 17
        p = printUdpHeader(length, p, temp);
        //printf("\n\n Protocol in use : UDP");
        return(p);
    }
    else{
        printf("\n Protocol in use is Neither TCP or UDP \n");
        exit(-1);
    }
}
unsigned char *printTcpHeader(int length, unsigned char *p, address *temp){
    if(length >= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr))){
        struct tcphdr *tcpHeader = (struct tcphdr *)p;
        
        //printf("\n\nTCP Header:\n");
        
        // Saving source and destination Port #
        temp->destPort = ntohs(tcpHeader->dest);
        temp->sourcePort = ntohs(tcpHeader->source);
             
    }       
    // Size of TCP header = 20
    return(p + sizeof(struct tcphdr));   
    
}
unsigned char *printUdpHeader(int length, unsigned char *p, address *temp){
    if(length >= (sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr))){
        struct udphdr *udpHeader = (struct udphdr *)p;
        
        //printf("\n\nUDP Header:\n");
        
        // Saving source and destination Port #
        temp->destPort = ntohs(udpHeader->dest);
        temp->sourcePort = ntohs(udpHeader->source);
        
        // Size of UDP header = 8
        return(p + sizeof(struct udphdr));       
    }    
}
void arrangeFlows(address *flows, address temp){
    
    int i = 0;
    bool newFlow = false; // To tell us if its a new flow or an old one
    
  
    // As long as something is different, continue loop
    while(!((strcmp(temp.destIP, flows[i].destIP) == 0)  && (strcmp(temp.sourceIP, flows[i].sourceIP) == 0)
        && (temp.destPort == flows[i].destPort) && (temp.sourcePort == flows[i].sourcePort))){
        
        // Break if end is reached
        if((flows[i].destPort == 0) && (flows[i].sourcePort == 0)
        && (flows[i].destIP[0] == '\0') && (flows[i].sourceIP[0] == '\0') ){
            newFlow = true;
            break;
        }
        else{
            i++;
        }    
    }
  
    if(newFlow == true){
        flows[i+1] = flows[i];
        flows[i] = temp;
        flows[i].numPackets = 1;
    }
    else if(newFlow == false){
        flows[i].numPackets = flows[i].numPackets +1;
    } 
}
void printFlows(address *flows){
    int i = 0;
    while(!((flows[i].destPort == 0) && (flows[i].sourcePort == 0)
        && (flows[i].destIP[0] == '\0') && (flows[i].sourceIP[0] == '\0'))){
        
        printf("\n\nNumber of Packets in flow: %d\n", flows[i].numPackets);
        printf("\tDestination IP %s\n", flows[i].destIP);
        printf("\tSource IP %s\n", flows[i].sourceIP);
        printf("\tDestination Port %d\n", flows[i].destPort);
        printf("\tSource Port %d\n", flows[i].sourcePort);
    i++;    
    }  
}

