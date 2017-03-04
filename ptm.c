//gcc ptm.c -o ptm -lpcap

#include <stdio.h>
#include <stdlib.h>
#include <pcap/pcap.h>

//NEED TO IMPLEMENT IN API:
//------------------------------------------------------------------------------
//1. pcap_create()	- create a live capture handle
//2. pcap_activate()	- activate a capture handle (start capturing)
//3. pcap_lookupdev() 	- will return the first device on that list that is not a ``loopback``
//4. pcap_next() 	- reads the next packet (by calling pcap_dispatch() with a cnt of 1)

//pcap_open_live()	- an old way to start capturing (before libpcap v1.0)

//------------------------------------------------------------------------------

//seq
//1. pcap_create()
//2. pcap_activate()

//pcap_findalldevs()	- obtain list of devices for live capturing

//error codes
#if 0
#define PCAP_ERROR			-1	/* generic error code */
#define PCAP_ERROR_BREAK		-2	/* loop terminated by pcap_breakloop */
#define PCAP_ERROR_NOT_ACTIVATED	-3	/* the capture needs to be activated */
#define PCAP_ERROR_ACTIVATED		-4	/* the operation can't be performed on already activated captures */
#define PCAP_ERROR_NO_SUCH_DEVICE	-5	/* no such device exists */
#define PCAP_ERROR_RFMON_NOTSUP		-6	/* this device doesn't support rfmon (monitor) mode */
#define PCAP_ERROR_NOT_RFMON		-7	/* operation supported only in monitor mode */
#define PCAP_ERROR_PERM_DENIED		-8	/* no permission to open the device */
#define PCAP_ERROR_IFACE_NOT_UP		-9	/* interface isn't up */
#define PCAP_ERROR_CANTSET_TSTAMP_TYPE	-10	/* this device doesn't support setting the time stamp type */
#define PCAP_ERROR_PROMISC_PERM_DENIED	-11	/* you don't have permission to capture in promiscuous mode */
#define PCAP_ERROR_TSTAMP_PRECISION_NOTSUP -12  /* the requested time stamp precision is not supported */
#endif

char errbuf[PCAP_ERRBUF_SIZE];	//256 bytes
int pkts_cnt = 0;

void main()
{
	int rv;
	char *iface = "wlan0";
	char *dev;
	struct pcap_pkthdr header;	/* The header that pcap gives us */
	const u_char *packet;		/* The actual packet */

	//1. looking for first available device
	dev = pcap_lookupdev(errbuf);
	if (!dev) 
	{
		printf("<error> couldn't find default device: %s\n", errbuf);
		exit(1);
	}
	else
		printf("device for capturing found is: %s\n", dev);	//on my pc its eth0 (probably first one)

	printf("start capture from iface: %s\n", iface);
	pcap_t *pcap = pcap_create(iface, errbuf);
	if (!pcap)
	{
		printf("<error> pcap_create()\n");
		exit(1);
	}

	rv = pcap_activate(pcap);
	if (rv)
	{
		printf("<error> pcap_activate(): %d. %s\n", rv, errbuf);
		exit(1);
	}

	while (1)
	{
		/* Grab a packet */
		packet = pcap_next(pcap, &header);
		//TODO: dump of header: macs, eth, tcp/udp, etc
		if (packet)
			printf("Jacked a packet #%d with length of [%d]\n", ++pkts_cnt, header.len);
	}
}
