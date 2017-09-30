#include "../include/optparse.h"
#include <pcap/pcap.h>
#include <iostream>
#include <string>
#include <vector>

using namespace std;

void pcap_handler_callback(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
	printf("%d\n", header->len);
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
    	cout<<expression;
    }
    const optparse::Values option = parser.parse_args(argc, argv);
    const std::vector<std::string> args = parser.args();
    
    if(option["interface"]=="" && option["file"]=="")
    {
		
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			return(2);
		}
		std::cout << dev;
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
	/* Grab a packet */
	packet = pcap_next(handle, &header);
	pcap_loop(handle, -1, pcap_handler_callback, NULL);
	/* Print its length */
	printf("Jacked a packet with length of [%d]\n", header.len);
	/* And close the session */
	pcap_close(handle);
	return(0);



    //if (options.get("string"))
    /*if (options["string"])
    {
        std::cout << options["file"] << "\n";
    }*/
}