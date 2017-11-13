# Passive-Network-Monitor
Design:

1)	The option parser- I’ve included a c++ option parser(optparse) to parse the command line options.
    Source: https://github.com/myint/optparse 

2)	User can provide the below mentioned 4 arguments to the application in the order in which they are written:
•	-i (interface)
•	-r (file)
•	-s (string)
•	expression

    mydump [-i interface] [-r file] [-s string] expression

    -i  Live capture from the network device <interface> (e.g., eth0). If not
        specified, mydump should automatically select a default interface to
        listen on (hint 1). Capture should continue indefinitely until the user
        terminates the program.

    -r Read packets from <file> in tcpdump format.

    -s Keep only packets that contain <string> in their payload (after any BPF
        filter is applied). You are not required to implement wildcard or regular
        expression matching. A simple string matching operation should suffice
        (hint 3).

    <expression> is a BPF filter that specifies which packets will be dumped. If
    no filter is given, all packets seen on the interface (or contained in the
    trace) should be dumped. Otherwise, only packets matching <expression> should
    be dumped

3)	Once the application is run, it checks if a pcap file has been provided (option –r) , if yes, the pcap file is picked up       and the packets captured inside it are analyzed. If the pcap file is not provided the application checks if an interface       to capture packets has been provided by the user (option –i).
    If the interface is also not provided, the default device is picked up.

4)	The pcap_handler_callback() function is called for every packet.

5)	It first checks if the packet is an IP Packet,
•	if not, the mac addresses and ether type of the packet (ARP or RARP or other) is printed and the application exits.
•	if yes, the IP and length, ether typed of the packet is printed. The application also checks the protocol type (TCP, UDP,     ICMP or other) of the packet and the corresponding pointers (to print the payload and other details like the port numbers)     are set.
    1.	TCP and UDP – port number and the payload is printed
    2.	ICMP and other – payload is printed
6)	A packet is picked up and printed only if the packet is a valid packet (valid packet- if the user has supplied a string that the packed should contain, only the packets with payloads containing that string are printed. If no string is provided all packets are valid packets.)   

Commands:

    Compile: make all

    Run: bin/mydump

References:

    http://www.tcpdump.org/pcap.html

    http://www.tcpdump.org/sniffex.c

