#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <libtrace.h>

#define LINKTYPE_ETHERNET 1

#if 0
int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)	- just stub
pcap_freealldevs(pcap_if_t *alldevs)
pcap_t *pcap_create(const char *source, char *errbuf)
int pcap_activate(pcap_t *p)
const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h)
#endif

struct pcap
{
	char name[30];
	int activated;
	int linktype;
	libtrace_t *trace;
};

#if 0
struct pcap_if {
        struct pcap_if *next;
        char *name;             /* name to hand to "pcap_open_live()" */
        char *description;      /* textual description of interface, or NULL */
        struct pcap_addr *addresses;
        bpf_u_int32 flags;      /* PCAP_IF_ interface flags */
};
#endif

//XXX - no such analogue in libtrace
int pcap_findalldevs(pcap_if_t **alldevsp, char *errbuf)
{





	return 0;
}

/*
 * Free a list of interfaces.
 */
void
pcap_freealldevs(pcap_if_t *alldevs)
{
        pcap_if_t *curdev, *nextdev;
        pcap_addr_t *curaddr, *nextaddr;

        for (curdev = alldevs; curdev != NULL; curdev = nextdev) {
                nextdev = curdev->next;

                /*
                 * Free all addresses.
                 */
                for (curaddr = curdev->addresses; curaddr != NULL; curaddr = nextaddr) {
                        nextaddr = curaddr->next;
                        if (curaddr->addr)
                                free(curaddr->addr);
                        if (curaddr->netmask)
                                free(curaddr->netmask);
                        if (curaddr->broadaddr)
                                free(curaddr->broadaddr);
                        if (curaddr->dstaddr)
                                free(curaddr->dstaddr);
                        free(curaddr);
                }

                /*
                 * Free the name string.
                 */
                free(curdev->name);

                /*
                 * Free the description string, if any.
                 */
                if (curdev->description != NULL)
                        free(curdev->description);

                /*
                 * Free the interface.
                 */
                free(curdev);
        }
}

//XXX - returns linktype which is always LINKTYPE_ETHERNET
int pcap_datalink(pcap_t *p)
{
        if (!p->activated)
                return (PCAP_ERROR_NOT_ACTIVATED);
        return (p->linktype);
}


//@source - iface name.
pcap_t *pcap_create(const char *source, char *errbuf)
{
	pcap_t *handle;
	handle = malloc(sizeof(pcap_t));
	if (!handle)
		return NULL;
	strcpy(handle->name, source);
	handle->activated = 0;
	handle->linktype = LINKTYPE_ETHERNET;

	handle->trace = trace_create(source);
	if (!handle->trace)
	{
		printf("failed to create trace\n");
		return NULL;
	}
	else
		printf("trace created successfully\n");

	return handle;
}

int pcap_activate(pcap_t *p)
{
	int rv;

	p->activated = 1;
	rv = trace_start(p->trace);

	return rv;
}


#if 0
struct pcap_pkthdr {
        struct timeval ts;      /* time stamp */
        bpf_u_int32 caplen;     /* length of portion present */
        bpf_u_int32 len;        /* length this packet (off wire) */
};
#endif

//pcap_next() reads the next packet (by calling pcap_dispatch() with a cnt of 1) and returns a u_char pointer to the data in that packet.
//The bytes of data from the packet begin with a link-layer header
const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h)
{
	int rv;
	libtrace_packet_t *packet = NULL;

	//alloc memory for packet and clear its fields
	packet = trace_create_packet();
	if (!packet)
		return NULL;

	//trace_read_packet (libtrace_t *trace, libtrace_packet_t *packet)
	//will block until a packet is read (or EOF is reached).
	rv = trace_read_packet(p->trace, packet);
	if (rv == 0)
		printf("EOF, no packets\n");
	else if (rv < 0)
		printf("error reading packet\n");
	else
	{
		h->len = trace_get_capture_length(packet);
	}

	if (rv)
		return (u_char*)packet;
	else
		return NULL;
}
