#include <stdio.h>
#include <pcap/pcap.h>
#include <libtrace.h>


pcap_t *pcap_create(const char *source, char *errbuf)
{

	//libtrace_t *trace_create(char *uri);
	libtrace_t *trace = NULL; 		//XXX - need to save it somewhere
	trace = trace_create(source);





}

