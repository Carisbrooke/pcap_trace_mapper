#!/bin/bash

IFACE="enp3s0"

if [ $# -eq 1 ]; then
	IFACE=$1
fi

#make && sudo ldconfig $PWD

export LIBPCAPTRACE_IFACE="enp3s0,odp:03:00.0"

cd /mnt/raw/src/tcpdumplibpcap/libpcapext/libpcap-1.7.4
cp libpcap.so.1.7.4 /mnt/raw/gdwk/pcap_trace_mapper/libpcap.so
cd -
sudo ldconfig $PWD
rm ptm
gcc ptm.c -o ptm -L./ -lpcap
sudo -E ./ptm $IFACE


# link with common libpcap
#gcc ptm.c -o ptm -lpcap
