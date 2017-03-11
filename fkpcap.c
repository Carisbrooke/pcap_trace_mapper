#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include <libtrace.h>

struct pcap
{
	char name[30];
	libtrace_t *trace;
};

pcap_t *pcap_create(const char *source, char *errbuf)
{
	pcap_t *handle;
	handle = malloc(sizeof(pcap_t));
	if (!handle)
		return NULL;
	strcpy(handle->name, source);

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
