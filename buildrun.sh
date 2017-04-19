#!/bin/bash

IFACE=""

if [ $# -eq 1 ]; then
	IFACE=$1
fi

#make && sudo ldconfig $PWD

cd /mnt/raw/src/tcpdumplibpcap/libpcapext/libpcap-1.7.4
cp libpcap.so.1.7.4 /mnt/raw/gdwk/pcap_trace_mapper/libpcap.so
cd -
sudo ldconfig $PWD
rm ptm
gcc ptm.c -o ptm -L./ -lpcap && sudo ./ptm $IFACE


# link with common libpcap
#gcc ptm.c -o ptm -lpcap
