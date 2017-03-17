#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap/pcap.h>
#include "dlt.h"
#include <libtrace.h>

#define LINKTYPE_ETHERNET 	1
#define MAXIMUM_SNAPLEN		262144

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
	int snapshot;
	int fd;
	libtrace_t *trace;
	libtrace_packet_t *packet;
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

struct dlt_choice {
        const char *name;
        const char *description;
        int     dlt;
};

#define DLT_CHOICE(code, description) { #code, description, DLT_ ## code }
#define DLT_CHOICE_SENTINEL { NULL, NULL, 0 }

static struct dlt_choice dlt_choices[] = {
        DLT_CHOICE(NULL, "BSD loopback"),
        DLT_CHOICE(EN10MB, "Ethernet"),
        DLT_CHOICE(IEEE802, "Token ring"),
        DLT_CHOICE(ARCNET, "BSD ARCNET"),
        DLT_CHOICE(SLIP, "SLIP"),
        DLT_CHOICE(PPP, "PPP"),
        DLT_CHOICE(FDDI, "FDDI"),
        DLT_CHOICE(ATM_RFC1483, "RFC 1483 LLC-encapsulated ATM"),
        DLT_CHOICE(RAW, "Raw IP"),
        DLT_CHOICE(SLIP_BSDOS, "BSD/OS SLIP"),
        DLT_CHOICE(PPP_BSDOS, "BSD/OS PPP"),
        DLT_CHOICE(ATM_CLIP, "Linux Classical IP-over-ATM"),
        DLT_CHOICE(PPP_SERIAL, "PPP over serial"),
        DLT_CHOICE(PPP_ETHER, "PPPoE"),
        DLT_CHOICE(SYMANTEC_FIREWALL, "Symantec Firewall"),
        DLT_CHOICE(C_HDLC, "Cisco HDLC"),
        DLT_CHOICE(IEEE802_11, "802.11"),
        DLT_CHOICE(FRELAY, "Frame Relay"),
        DLT_CHOICE(LOOP, "OpenBSD loopback"),
        DLT_CHOICE(ENC, "OpenBSD encapsulated IP"),
        DLT_CHOICE(LINUX_SLL, "Linux cooked"),
        DLT_CHOICE(LTALK, "Localtalk"),
        DLT_CHOICE(PFLOG, "OpenBSD pflog file"),
        DLT_CHOICE(PFSYNC, "Packet filter state syncing"),
        DLT_CHOICE(PRISM_HEADER, "802.11 plus Prism header"),
        DLT_CHOICE(IP_OVER_FC, "RFC 2625 IP-over-Fibre Channel"),
        DLT_CHOICE(SUNATM, "Sun raw ATM"),
        DLT_CHOICE(IEEE802_11_RADIO, "802.11 plus radiotap header"),
        DLT_CHOICE(ARCNET_LINUX, "Linux ARCNET"),
        DLT_CHOICE(JUNIPER_MLPPP, "Juniper Multi-Link PPP"),
        DLT_CHOICE(JUNIPER_MLFR, "Juniper Multi-Link Frame Relay"),
        DLT_CHOICE(JUNIPER_ES, "Juniper Encryption Services PIC"),
        DLT_CHOICE(JUNIPER_GGSN, "Juniper GGSN PIC"),
        DLT_CHOICE(JUNIPER_MFR, "Juniper FRF.16 Frame Relay"),
        DLT_CHOICE(JUNIPER_ATM2, "Juniper ATM2 PIC"),
        DLT_CHOICE(JUNIPER_SERVICES, "Juniper Advanced Services PIC"),
        DLT_CHOICE(JUNIPER_ATM1, "Juniper ATM1 PIC"),
        DLT_CHOICE(APPLE_IP_OVER_IEEE1394, "Apple IP-over-IEEE 1394"),
        DLT_CHOICE(MTP2_WITH_PHDR, "SS7 MTP2 with Pseudo-header"),
        DLT_CHOICE(MTP2, "SS7 MTP2"),
        DLT_CHOICE(MTP3, "SS7 MTP3"),
        DLT_CHOICE(SCCP, "SS7 SCCP"),
        DLT_CHOICE(DOCSIS, "DOCSIS"),
        DLT_CHOICE(LINUX_IRDA, "Linux IrDA"),
        DLT_CHOICE(IEEE802_11_RADIO_AVS, "802.11 plus AVS radio information header"),
        DLT_CHOICE(JUNIPER_MONITOR, "Juniper Passive Monitor PIC"),
        DLT_CHOICE(BACNET_MS_TP, "BACnet MS/TP"),
        DLT_CHOICE(PPP_PPPD, "PPP for pppd, with direction flag"),
        DLT_CHOICE(JUNIPER_PPPOE, "Juniper PPPoE"),
        DLT_CHOICE(JUNIPER_PPPOE_ATM, "Juniper PPPoE/ATM"),
        DLT_CHOICE(GPRS_LLC, "GPRS LLC"),
        DLT_CHOICE(GPF_T, "GPF-T"),
        DLT_CHOICE(GPF_F, "GPF-F"),
        DLT_CHOICE(JUNIPER_PIC_PEER, "Juniper PIC Peer"),
        DLT_CHOICE(ERF_ETH,     "Ethernet with Endace ERF header"),
        DLT_CHOICE(ERF_POS, "Packet-over-SONET with Endace ERF header"),
        DLT_CHOICE(LINUX_LAPD, "Linux vISDN LAPD"),
        DLT_CHOICE(JUNIPER_ETHER, "Juniper Ethernet"),
        DLT_CHOICE(JUNIPER_PPP, "Juniper PPP"),
        DLT_CHOICE(JUNIPER_FRELAY, "Juniper Frame Relay"),
        DLT_CHOICE(JUNIPER_CHDLC, "Juniper C-HDLC"),
        DLT_CHOICE(MFR, "FRF.16 Frame Relay"),
        DLT_CHOICE(JUNIPER_VP, "Juniper Voice PIC"),
        DLT_CHOICE(A429, "Arinc 429"),
        DLT_CHOICE(A653_ICM, "Arinc 653 Interpartition Communication"),
        DLT_CHOICE(USB_FREEBSD, "USB with FreeBSD header"),
        DLT_CHOICE(BLUETOOTH_HCI_H4, "Bluetooth HCI UART transport layer"),
        DLT_CHOICE(IEEE802_16_MAC_CPS, "IEEE 802.16 MAC Common Part Sublayer"),
        DLT_CHOICE(USB_LINUX, "USB with Linux header"),
        DLT_CHOICE(CAN20B, "Controller Area Network (CAN) v. 2.0B"),
        DLT_CHOICE(IEEE802_15_4_LINUX, "IEEE 802.15.4 with Linux padding"),
        DLT_CHOICE(PPI, "Per-Packet Information"),
        DLT_CHOICE(IEEE802_16_MAC_CPS_RADIO, "IEEE 802.16 MAC Common Part Sublayer plus radiotap header"),
        DLT_CHOICE(JUNIPER_ISM, "Juniper Integrated Service Module"),
        DLT_CHOICE(IEEE802_15_4, "IEEE 802.15.4 with FCS"),
        DLT_CHOICE(SITA, "SITA pseudo-header"),
        DLT_CHOICE(ERF, "Endace ERF header"),
        DLT_CHOICE(RAIF1, "Ethernet with u10 Networks pseudo-header"),
        DLT_CHOICE(IPMB, "IPMB"),
        DLT_CHOICE(JUNIPER_ST, "Juniper Secure Tunnel"),
        DLT_CHOICE(BLUETOOTH_HCI_H4_WITH_PHDR, "Bluetooth HCI UART transport layer plus pseudo-header"),
        DLT_CHOICE(AX25_KISS, "AX.25 with KISS header"),
        DLT_CHOICE(IEEE802_15_4_NONASK_PHY, "IEEE 802.15.4 with non-ASK PHY data"),
        DLT_CHOICE(MPLS, "MPLS with label as link-layer header"),
        DLT_CHOICE(LINUX_EVDEV, "Linux evdev events"),
        DLT_CHOICE(USB_LINUX_MMAPPED, "USB with padded Linux header"),
        DLT_CHOICE(DECT, "DECT"),
        DLT_CHOICE(AOS, "AOS Space Data Link protocol"),
        DLT_CHOICE(WIHART, "Wireless HART"),
        DLT_CHOICE(FC_2, "Fibre Channel FC-2"),
        DLT_CHOICE(FC_2_WITH_FRAME_DELIMS, "Fibre Channel FC-2 with frame delimiters"),
        DLT_CHOICE(IPNET, "Solaris ipnet"),
        DLT_CHOICE(CAN_SOCKETCAN, "CAN-bus with SocketCAN headers"),
        DLT_CHOICE(IPV4, "Raw IPv4"),
        DLT_CHOICE(IPV6, "Raw IPv6"),
        DLT_CHOICE(IEEE802_15_4_NOFCS, "IEEE 802.15.4 without FCS"),
        DLT_CHOICE(DBUS, "D-Bus"),
        DLT_CHOICE(JUNIPER_VS, "Juniper Virtual Server"),
        DLT_CHOICE(JUNIPER_SRX_E2E, "Juniper SRX E2E"),
        DLT_CHOICE(JUNIPER_FIBRECHANNEL, "Juniper Fibre Channel"),
        DLT_CHOICE(DVB_CI, "DVB-CI"),
        DLT_CHOICE(MUX27010, "MUX27010"),
        DLT_CHOICE(STANAG_5066_D_PDU, "STANAG 5066 D_PDUs"),
        DLT_CHOICE(JUNIPER_ATM_CEMIC, "Juniper ATM CEMIC"),
        DLT_CHOICE(NFLOG, "Linux netfilter log messages"),
        DLT_CHOICE(NETANALYZER, "Ethernet with Hilscher netANALYZER pseudo-header"),
       	DLT_CHOICE(NETANALYZER_TRANSPARENT, "Ethernet with Hilscher netANALYZER pseudo-header and with preamble and SFD"),
        DLT_CHOICE(IPOIB, "RFC 4391 IP-over-Infiniband"),
        DLT_CHOICE(MPEG_2_TS, "MPEG-2 transport stream"),
        DLT_CHOICE(NG40, "ng40 protocol tester Iub/Iur"),
        DLT_CHOICE(NFC_LLCP, "NFC LLCP PDUs with pseudo-header"),
        DLT_CHOICE(INFINIBAND, "InfiniBand"),
        DLT_CHOICE(SCTP, "SCTP"),
        DLT_CHOICE(USBPCAP, "USB with USBPcap header"),
        DLT_CHOICE(RTAC_SERIAL, "Schweitzer Engineering Laboratories RTAC packets"),
        DLT_CHOICE(BLUETOOTH_LE_LL, "Bluetooth Low Energy air interface"),
        DLT_CHOICE(NETLINK, "Linux netlink"),
        DLT_CHOICE(BLUETOOTH_LINUX_MONITOR, "Bluetooth Linux Monitor"),
        DLT_CHOICE(BLUETOOTH_BREDR_BB, "Bluetooth Basic Rate/Enhanced Data Rate baseband packets"),
        DLT_CHOICE(BLUETOOTH_LE_LL_WITH_PHDR, "Bluetooth Low Energy air interface with pseudo-header"),
        DLT_CHOICE(PROFIBUS_DL, "PROFIBUS data link layer"),
        DLT_CHOICE(PKTAP, "Apple DLT_PKTAP"),
        DLT_CHOICE(EPON, "Ethernet with 802.3 Clause 65 EPON preamble"),
        DLT_CHOICE(IPMI_HPM_2, "IPMI trace packets"),
        DLT_CHOICE(ZWAVE_R1_R2, "Z-Wave RF profile R1 and R2 packets"),
        DLT_CHOICE(ZWAVE_R3, "Z-Wave RF profile R3 packets"),
        DLT_CHOICE(WATTSTOPPER_DLM, "WattStopper Digital Lighting Management (DLM) and Legrand Nitoo Open protocol"),
        DLT_CHOICE(ISO_14443, "ISO 14443 messages"),
        DLT_CHOICE(RDS, "IEC 62106 Radio Data System groups"),
        DLT_CHOICE_SENTINEL
};




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

const char *
pcap_datalink_val_to_name(int dlt)
{
        int i;

        for (i = 0; dlt_choices[i].name != NULL; i++) {
                if (dlt_choices[i].dlt == dlt)
                        return (dlt_choices[i].name);
        }
        return (NULL);
}

const char *
pcap_datalink_val_to_description(int dlt)
{
        int i;

        for (i = 0; dlt_choices[i].name != NULL; i++) {
                if (dlt_choices[i].dlt == dlt)
                        return (dlt_choices[i].description);
        }
        return (NULL);
}

void pcap_close(pcap_t *p)
{
	if (p->packet)
		trace_destroy_packet(p->packet);
	if (p->trace)
		trace_destroy(p->trace);
        free(p);
}

//XXX - stub!
pcap_t *pcap_open_offline(const char *fname, char *errbuf)
{
        return NULL;
}

//@source - iface name.
pcap_t *pcap_create(const char *source, char *errbuf)
{
	pcap_t *handle;
	handle = malloc(sizeof(pcap_t));
	if (!handle)
		return NULL;

	//init our pcap structure
	strcpy(handle->name, source);
	handle->activated = 0;
	handle->packet = NULL;
	handle->linktype = LINKTYPE_ETHERNET;
	handle->snapshot = 65536;
	handle->fd = 7777;

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

//internal function, not in my list
int pcap_check_activated(pcap_t *p)
{
        if (p->activated) 
	{
                printf("can't perform operation on activated capture\n");
                return (-1);
        }
        return (0);
}

int pcap_set_snaplen(pcap_t *p, int snaplen)
{
        if (pcap_check_activated(p))
                return (PCAP_ERROR_ACTIVATED);

        /*
         * Turn invalid values, or excessively large values, into
         * the maximum allowed value.
         *
         * If some application really *needs* a bigger snapshot
         * length, we should just increase MAXIMUM_SNAPLEN.
         */
        if (snaplen <= 0 || snaplen > MAXIMUM_SNAPLEN)
                snaplen = MAXIMUM_SNAPLEN;
        p->snapshot = snaplen;
        return (0);
}

//we just have a define in libtrace, but not a function to set buf size,
//so this is just stub here
//#define LIBTRACE_PACKET_BUFSIZE   65536

int pcap_set_buffer_size(pcap_t *p, int buffer_size)
{
        if (pcap_check_activated(p))
                return (PCAP_ERROR_ACTIVATED);
        if (buffer_size <= 0) {
                /*
                 * Silently ignore invalid values.
                 */
                return (0);
        }
	//XXX - don't do actually nothing here
        //p->opt.buffer_size = buffer_size;
        return (0);
}

int pcap_set_promisc(pcap_t *p, int promisc)
{
        if (pcap_check_activated(p))
                return (PCAP_ERROR_ACTIVATED);

	trace_set_promisc(p->trace, (bool)promisc);

        return (0);
}

//so this is just stub here
int pcap_set_timeout(pcap_t *p, int timeout_ms)
{
        if (pcap_check_activated(p))
                return (PCAP_ERROR_ACTIVATED);
	//XXX - don't do actually nothing here
        //p->opt.timeout = timeout_ms;
        return (0);
}

int pcap_activate(pcap_t *p)
{
	int rv;

	p->activated = 1;
	rv = trace_start(p->trace);

	return rv;
}

int pcap_snapshot(pcap_t *p)
{
        if (!p->activated)
                return (PCAP_ERROR_NOT_ACTIVATED);
        return (p->snapshot);
}

int pcap_fileno(pcap_t *p)
{
        return (p->fd);
}

int pcap_setnonblock(pcap_t *p, int nonblock, char *errbuf)
{
        int ret;

	ret = nonblock;
//stub  
#if 0
        ret = p->setnonblock_op(p, nonblock, errbuf);
        if (ret == -1) { 
                /*
                 * In case somebody depended on the bug wherein
                 * the error message was put into p->errbuf
                 * by pcap_setnonblock_fd().
                 */
                strlcpy(p->errbuf, errbuf, PCAP_ERRBUF_SIZE);
        }           
#endif
        return (ret);
}



#if 0
struct pcap_pkthdr {
        struct timeval ts;      /* time stamp */
        bpf_u_int32 caplen;     /* length of portion present */
        bpf_u_int32 len;        /* length this packet (off wire) */
};
#endif

int pcap_dispatch(pcap_t *p, int cnt, pcap_handler callback, u_char *user)
{




}


//pcap_next() reads the next packet (by calling pcap_dispatch() with a cnt of 1) and returns a u_char pointer to the data in that packet.
//The bytes of data from the packet begin with a link-layer header
const u_char *pcap_next(pcap_t *p, struct pcap_pkthdr *h)
{
	int rv;

	//alloc memory for packet and clear its fields
	p->packet = trace_create_packet();
	if (!p->packet)
		return NULL;

	//trace_read_packet (libtrace_t *trace, libtrace_packet_t *packet)
	//will block until a packet is read (or EOF is reached).
	rv = trace_read_packet(p->trace, p->packet);
	if (rv == 0)
		printf("EOF, no packets\n");
	else if (rv < 0)
		printf("error reading packet\n");
	else
	{
		h->len = trace_get_capture_length(p->packet);
	}

	if (rv)
		return (u_char*)p->packet;
	else
		return NULL;
}
