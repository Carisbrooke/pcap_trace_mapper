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
	strcpy(handle->name, "eth0"); //XXX - just an example of what we save here

	libtrace_t *trace = NULL;
	trace = trace_create(source);
	if (!trace)
		return NULL;
	else
		handle->trace = trace;

	return handle;
}

int pcap_activate(pcap_t *p)
{
	int rv;
	rv = trace_start(p->trace);

	return rv;
}
