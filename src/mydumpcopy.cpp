#include "../include/optparse.h"
#include <pcap/pcap.h>
#include <iostream>
#include <stdio.h>
#include <string>
#include <vector>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <ctime>
//using namespace std;
/*char * stringToCharPointer(string s)
{

}*/
#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6

//#define	ETHERTYPE_PUP		0x0200      /* Xerox PUP */
#define	ETHERTYPE_IP		0x0800		/* IP */
#define	ETHERTYPE_ARP		0x0806		/* Address resolution */
//#define	ETHERTYPE_REVARP	0x8035		/* Reverse ARP */
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

void print_hex_ascii_line(const u_char *payload, int len, int offset)
{

	int i;
	int gap;
	const u_char *ch;

	/* offset */
	printf("%05d   ", offset);
	
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
	ch = payload;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			printf("%c", *ch);
		else
			printf(".");
		ch++;
	}

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
	u_char *payload;                    /* Packet payload */

	int size_ip;
	int size_tcp;
	int size_payload;
	
	u_char *ptr;
	int i;

	printf("\nPacket number %d:", count);
	count++;

	/*time Stamp*/
	printf("\nRecieved at %s",ctime((const time_t *)&header->ts.tv_sec));
	
	/* define ethernet header */
	ethernet = (struct sniff_ethernet*)(packet);

	ptr = ethernet->ether_dhost;
    i = ETHER_ADDR_LEN;
    printf(" Destination Address:  ");
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    printf("\n");

    ptr = ethernet->ether_shost;
    i = ETHER_ADDR_LEN;
    printf(" Source Address:  ");
    do{
        printf("%s%x",(i == ETHER_ADDR_LEN) ? " " : ":",*ptr++);
    }while(--i>0);
    printf("\n");
	

	/* Do a couple of checks to see what packet type we have..*/
    if (ntohs (ethernet->ether_type) == ETHERTYPE_IP)
    {
        printf("Ethernet type hex:0x%x. It is an IP packet\n",
                ntohs(ethernet->ether_type),
                ntohs(ethernet->ether_type));
    }else  if (ntohs (ethernet->ether_type) == ETHERTYPE_ARP)
    {
        printf("Ethernet type hex:0x%x. It is an ARP packet\n",
                ntohs(ethernet->ether_type));
                //ntohs(ethernet->ether_type));
    }else {
        printf("Ethernet type 0x%x. It is not IP or ARP", ntohs(ethernet->ether_type));
        //exit(1);
    }
	
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
	

	

	


	
	/* print source and destination IP addresses */
		printf("From: %s\n", inet_ntoa(ip->ip_src));
		printf("To: %s\n", inet_ntoa(ip->ip_dst));

	

	
	


		printf("len %d", header->len);



	/* determine protocol */	
		switch(ip->ip_p) 
		{
			case IPPROTO_TCP:
				printf("   Protocol: TCP\n");



				tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
				size_tcp = TH_OFF(tcp)*4;
				if (size_tcp < 20) 
				{
					printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
					return;
				}
	
				printf("   Src port: %d\n", ntohs(tcp->th_sport));
				printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	
				/* define/compute tcp payload (segment) offset */
				payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
	
				/* compute tcp payload (segment) size */
				size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	
				/*
				 * Print payload data; it might be binary, so don't just
				 * treat it as a string.
	 			*/
				if (size_payload > 0) 
				{
					printf("   Payload (%d bytes):\n", size_payload);
					print_payload(payload, size_payload);
				}


				return;
			case IPPROTO_UDP:
				printf("   Protocol: UDP\n");
				return;
			case IPPROTO_ICMP:
				printf("   Protocol: ICMP\n");
				return;
			case IPPROTO_IP:
				printf("   Protocol: IP\n");
				return;
			default:
				printf("   Protocol: unknown\n");
				return;
		}
		/* define/compute tcp header offset */
		




		/*tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		if (size_tcp < 20) 
		{
			printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}
		printf("   Src port: %d\n", ntohs(tcp->th_sport));
		printf("   Dst port: %d\n", ntohs(tcp->th_dport));*/
		





		/* define/compute tcp header offset */
		/*tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
		size_tcp = TH_OFF(tcp)*4;
		if (size_tcp < 20) {
			printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
			return;
		}
	
		printf("   Src port: %d\n", ntohs(tcp->th_sport));
		printf("   Dst port: %d\n", ntohs(tcp->th_dport));
	
		payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
		size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
		if (size_payload > 0) 
		{
			printf("   Payload (%d bytes):\n", size_payload);
			print_payload(payload, size_payload);
		}*/
	}
	return;
	//printf("Recieved at %s\n",ctime((const time_t *)&header->ts.tv_sec));
	//printf("%d\n", header->len);
	
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
    //parser.add_option("-q", "--quiet").action("store_false").dest("verbose").set_default("1").help("don't print status messages to stdout");
    parser.add_option("-s").dest("string");
    
    if(argc%2==0)
    {
    	expression = argv[argc-1];
    	printf("The expression = %s",expression);
    }
    const optparse::Values option = parser.parse_args(argc, argv);
    const std::vector<std::string> args = parser.args();
    if(option["interface"]=="" )//&& option["file"]=="")
    {
		//dev = new char [option["interface"].length()+1];
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
    }
    else
 	{
 		dev = (char*)malloc(sizeof(option["interface"].length()+1));
 		strcpy(dev, option["interface"].c_str());
    	printf("\ndev=%s",dev);
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
	
	/* make sure we're capturing on an Ethernet device [2] */
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
	}
	if (pcap_setfilter(handle, &fp) == -1) 
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", expression, pcap_geterr(handle));
		return(2);
	}
	//Grab a packet 
	//packet = pcap_next(handle, &header);
	pcap_loop(handle, 0, pcap_handler_callback, NULL);
	// And close the session 
	pcap_close(handle);
	return(0);



    //if (options.get("string"))
    /*if (options["string"])
    {
        std::cout << options["file"] << "\n";
    }*/
}