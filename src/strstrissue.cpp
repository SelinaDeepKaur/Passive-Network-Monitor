#include "../include/optparse.h"
#include <pcap/pcap.h>
#include <iostream>
#include <stdio.h>
#include <string>
#include <vector>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <time.h>

#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6

//#define	ETHERTYPE_PUP		0x0200      /* Xerox PUP */
#define	ETHERTYPE_IP		0x0800		/* IP */
#define	ETHERTYPE_ARP		0x0806		/* Address resolution */
#define	ETHERTYPE_RARP		0x8035		/* Reverse ARP */
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* Ethernet header */
typedef u_int tcp_seq;
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
	
struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;  
 
              /* data offset, rsvd */
		#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};
struct sniff_udp {
         u_short uh_sport;               /* source port */
         u_short uh_dport;               /* destination port */
         u_short uh_ulen;                /* udp length */
         u_short uh_sum;                 /* udp checksum */
		 #define SIZE_UDP 8
		

};

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;
	

	/* offset */
	//printf("%05d   ", offset);
	printf(" ");
	/* hex */
	ch = payload;
	for(i = 0; i < len; i++) {
		printf("%02x ", *ch);
		ch++;
		/* print extra space after 8th byte for visual aid */
		if (i == 7)
			printf(" ");
	}
	/* print space to handle line less than 8 bytes */
	if (len < 8)
		printf(" ");
	
	/* fill hex gap with spaces if not full line */
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			printf("   ");
		}
	}
	printf("   ");
	
	/* ascii (if printable) */
	// ch = payload;
	// for(i = 0; i < len; i++) {
	// 	if (isprint(*ch))
	// 		printf("%c", *ch);
	// 	else
	// 		printf(".");
	// 	ch++;
	// }

	
	char *payloadCopy = (char *)malloc(len);
	char *payloadCopyPtr = payloadCopy;
	char c;
	
	
	//printf("Memcpy1-------");
	memcpy(payloadCopy,payload,len);
	//printf("Memcpy2-------");
	//printf("%s\n",payloadCopy);
	for(i = 0; i < len; i++) {
		if(isprint(*payloadCopyPtr))
		{
			
			*payloadCopyPtr++;
		}
		else
		{
			c='@';
			//strcpy(c,".");
			*payloadCopyPtr=c;
			//*payloadCopy=".";
			*payloadCopyPtr++;
		}

	
	}
	//printf("Storing the payload wala print-----------------------");
	printf("%s\n",payloadCopy);
	//printf("--------------------Just printed itttt");


	// printf("Storing the payload wala print-----------------------");
	// printf("%s\n",payloadCopy);
	// printf("--------------------Just printed itttt");



	printf("\n");

return;
}
void print_payload(const u_char *payload, int len)
{

	int len_rem = len;
	int line_width = 16;			//number of bytes per line 
	int line_len;
	int offset = 0;					//zero-based offset counter 
	const u_char *ch = payload;

	if (len <= 0)
		return;

	// data fits on one line 
	if (len <= line_width) {
		print_hex_ascii_line(ch, len, offset);
		return;
	}

	// data spans multiple lines 
	for ( ;; ) {
		// compute current line length 
		line_len = line_width % len_rem;
		// print line 
		print_hex_ascii_line(ch, line_len, offset);
		//compute total remaining 
		len_rem = len_rem - line_len;
		//shift pointer to remaining bytes to print 
		ch = ch + line_len;
		//add offset 
		offset = offset + line_width;
		//check if we have line width chars or less 
		if (len_rem <= line_width) {
			// print last line and get out 
			print_hex_ascii_line(ch, len_rem, offset);
			break;
		}
	}

return;
}

void pcap_handler_callback(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
	static int count = 1;                   /* packet counter */
	
	//declare pointers to packet headers 
	struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
	struct sniff_ip *ip;              /* The IP header */
	struct sniff_tcp *tcp;            /* The TCP header */
	struct sniff_udp *udp;

	u_char *payload;                    /* Packet payload */

	int size_ip;
	int size_protocol;
	int size_payload;
	int validPacket=-1;
	char buffer[80];
	struct tm * timeinfo; 
	u_char *ptr;
	int i;
	

	

	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);
    /* define/compute ip header offset */
	if(ntohs (ethernet->ether_type) == ETHERTYPE_IP)
	{
		ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
		size_ip = IP_HL(ip)*4;
		//size_ip = (((ip)->ip_vhl) & 0x0f)*4;
		if (size_ip < 20) 
		{
			printf("* Invalid IP header length: %u bytes\n", size_ip);
			return;
		}
	


		//printf("len %d", ntohs(ip->ip_len));


		//int flag=-1;

		std::string protocolName;
		int srcPort = -1;
		int destPort = -1;
	/* determine protocol */	
		switch(ip->ip_p) 
		{
			case IPPROTO_TCP:
				protocolName = "TCP";

				tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
				//char *p= tcp;
				//size_tcp = TH_OFF(tcp)*4;
				size_protocol= TH_OFF(tcp)*4;
				if (size_protocol < 20) 
				{
					printf("   * Invalid TCP header length: %u bytes\n", size_protocol);
					return;
				}
	
				srcPort = ntohs(tcp->th_sport);
				destPort = ntohs(tcp->th_dport);
	
				/* define/compute tcp payload (segment) offset */
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_protocol);
				/* compute tcp payload (segment) size */
				size_payload = ntohs(ip->ip_len) - (size_ip + size_protocol);
	
				/*
				 * Print payload data; it might be binary, so don't just
				 * treat it as a string.
	 			*/


				break;

			case IPPROTO_UDP:
				//flUDP1;
				protocolName = "UDP";
				//printf("UDP-------");
				//printf("   Protocol: UDP\n");
				udp=(struct sniff_udp*)(packet + SIZE_ETHERNET + size_ip);
				size_protocol = SIZE_UDP;

				srcPort = ntohs(udp->uh_sport);
				destPort = ntohs(udp->uh_dport);
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_protocol);
				size_payload = ntohs(ip->ip_len) - (size_ip + size_protocol);
				// printf("Memcpy3-------");
				// if (size_payload > 0)
				// {
				// 	//printf("%s\n",payload);
				// 	char *payloadCopy = (char *)malloc(size_payload);;
				// 	char *payloadCopyPtr = payloadCopy;
				// 	char c;
					
					
				// 	printf("Memcpy1-------");
				// 	memcpy(payloadCopy, payload,size_payload);
				// 	printf("Memcpy2-------");
				// 	printf("%s\n",payload);
				// 	for(i = 0; i < size_payload; i++) {
				// 		if(isprint(*payloadCopyPtr))
				// 		{
							
				// 			*payloadCopyPtr++;
				// 		}
				// 		else
				// 		{
				// 			c='.';
				// 			//strcpy(c,".");
				// 			*payloadCopyPtr=c;
				// 			//*payloadCopy=".";
				// 			*payloadCopyPtr++;
				// 		}


				// //printf("%c", *ch);
				// //else
				// //	printf(".");
					
				// 	}
				// 	printf("Storing the payload wala print-----------------------");
				// 	printf("%s\n",payloadCopy);
				// 	printf("--------------------Just printed itttt");
				// }
				

				break;
			case IPPROTO_ICMP:
				//flag=2;
				protocolName = "ICMP";
				//printf("   Protocol: ICMP\n");

				/*size of ICMP header is 8 bytes*/;
				size_protocol = 8;
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_protocol);

				size_payload = ntohs(ip->ip_len) - (size_ip + size_protocol);

				break;
			
			default:
				//flag=3;
				protocolName = "Unknown Protocol";
				//printf("   Protocol: unknown\n");
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip);

				size_payload = ntohs(ip->ip_len) - size_ip;

				/*if(size_payload > 0)
				{
					printf("   Payload (%d bytes:\n", size_payload);
					print_payload(payload, size_payload);
				}*/

				break;
		}
		//printf("\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\n\nTHE FINASLLLLLLL FORMATTTTTTT\n");
		
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_protocol);
		//printf("SELINAaaaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAaaaaaaaaaaaaaaa\n");
		//printf("argument=%s\n",(char *)args);
		//printf("payload=%s\n", payload);

		if(args==NULL)
		{
			validPacket=1;
			//printf("\n-s option not passed\n");
		}
		else if(args!=NULL&&strstr((char *)payload,(char *)args))
		{
			validPacket=1;
			//printf("\nMATCHINGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG\n");
		}
		if(validPacket==1)
		{
			//printf("\nVALIDDDDDDDDDDDDDDDDDDPACKETTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT\n");

		

			//printf("\n Packet number %d:", count);
			count++;
			timeinfo = localtime((const time_t *)&header->ts.tv_sec);
			strftime(buffer,80,"%Y-%m-%d",timeinfo);
			printf("\n %s\n",buffer);
			printf("\n %s",ctime((const time_t *)&header->ts.tv_sec));

			ptr = ethernet->ether_shost;
			i = ETHER_ADDR_LEN;

			//printf(" Source Address:  ");
			do{
				printf("%s%02x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
			}while(--i>0);
			printf(" ->");

			ptr = ethernet->ether_dhost;
			i = ETHER_ADDR_LEN;
			//printf(" Destination Address:  ");
			do{
				printf("%s%02x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
			}while(--i>0);
			//printf(" ");

			

			printf(" type 0x%x (IP packet)",ntohs(ethernet->ether_type));
			printf(" len %d", ntohs(ip->ip_len));
			printf("\n %s:", inet_ntoa(ip->ip_src));
			if(srcPort!=-1)
				printf("%d",srcPort);
			printf(" -> %s:", inet_ntoa(ip->ip_dst));
			if(destPort!=-1)
				printf("%d",destPort);

			printf(" %s\n",protocolName.c_str()); 


			if (size_payload > 0) 
			{
				//printf("   Payload (%d bytes):\n", size_payload);
				print_payload(payload, size_payload);
			}
		

		}

		/* define/compute tcp header offset */
	
	}
	else
	{
		//printf("\nIT IS NOT AN IP PACKET");
		count++;
		timeinfo = localtime((const time_t *)&header->ts.tv_sec);
		strftime(buffer,80,"%Y-%m-%d",timeinfo);
		printf("\n %s\n",buffer);
		//strftime(buffer,80,"%Y-%m-%d",(const time_t *)&header->ts.tv_sec);
		//printf("\n %s",buffer);
		printf("\n %s",ctime((const time_t *)&header->ts.tv_sec));
		//std::cout<<buffer;

		ptr = ethernet->ether_shost;
		i = ETHER_ADDR_LEN;

		//printf(" Source Address:  ");
		do{
			printf("%s%02x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
		}while(--i>0);
		printf(" -> ");

		ptr = ethernet->ether_dhost;
		i = ETHER_ADDR_LEN;
		//printf(" Destination Address:  ");
		do{
			printf("%s%02x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
		}while(--i>0);

		if (ntohs (ethernet->ether_type) == ETHERTYPE_ARP)
    	{
        	printf(" type 0x%x (ARP packet) ", ntohs(ethernet->ether_type));
                //ntohs(ethernet->ether_type));
    	}
    	else if (ntohs(ethernet->ether_type) == ETHERTYPE_RARP)
		{
			printf(" type 0x%x (RARP packet)", ntohs(ethernet->ether_type));
		}
    	
		else
    	{
        	printf(" type 0x%x (not IP or ARP or RARP)\n", ntohs(ethernet->ether_type));
        //exit(1);
    	}

	}
	return;
	
}
int main(int argc, char **argv)
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE], *expression=NULL;
	struct bpf_program fp;
	bpf_u_int32 mask;		/* The netmask of our sniffing device */
	bpf_u_int32 net;
	pcap_t *handle;
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;
    optparse::OptionParser parser =optparse::OptionParser().description("Option Parser");
    parser.add_option("-i").dest("interface");
    parser.add_option("-r").dest("file");
    parser.add_option("-s").dest("string");
   
    if(argc%2==0)
    {
    	
    	expression = argv[argc-1];
    }
    const optparse::Values option = parser.parse_args(argc, argv);
    const std::vector<std::string> args = parser.args();

    if(option["file"]!="")
    {

    	handle = pcap_open_offline(option["file"].c_str(), errbuf);
    	if (handle == NULL) 
		{
			fprintf(stderr, "Couldn't open pcap file %s: %s\n", option["file"].c_str(), errbuf);
			return(2);
		}
    }
    else
    {
    	if(option["interface"]!="" )
    	{
    		dev = (char*)malloc(sizeof(option["interface"].length()+1));
 			strcpy(dev, option["interface"].c_str());
    		printf("\ndev=%s",dev);	
    	}
    	else
    	{
    		dev = pcap_lookupdev(errbuf);
			if (dev == NULL) {
				fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
				return(2);
				}
    	}
    	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) 
    	{
			fprintf(stderr, "Can't get netmask for device %s\n", dev);
			net = 0;
			mask = 0;
	 	}

		handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		if (handle == NULL) 
		{
			fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
			return(2);
		}
    }
	
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet\n", dev);
		exit(EXIT_FAILURE);
	}

	if(expression)
	{
		if (pcap_compile(handle, &fp, expression, 0, net) == -1) 
		{
			fprintf(stderr, "Couldn't parse filter %s: %s\n", expression, pcap_geterr(handle));
			return(2);
		}
		if (pcap_setfilter(handle, &fp) == -1) 
		{
			fprintf(stderr, "Couldn't install filter %s: %s\n", expression, pcap_geterr(handle));
			return(2);
		}
	}
	
	if(option["string"]!="")
		pcap_loop(handle, 0, pcap_handler_callback, (u_char *)option["string"].c_str());
	else
		pcap_loop(handle, 0, pcap_handler_callback, NULL);

	pcap_close(handle);
	return(0);

}