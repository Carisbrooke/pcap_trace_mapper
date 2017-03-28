#!/bin/bash

IFACE=""

if [ $# -eq 1 ]; then
	IFACE=$1
fi

make && sudo ldconfig $PWD
gcc ptm.c -o ptm -L./ -lpcap && sudo ./ptm $IFACE


# link with common libpcap
#gcc ptm.c -o ptm -lpcap
