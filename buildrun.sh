#!/bin/bash

IFACE=""

if [ $# -eq 1 ]; then
	IFACE=$1
fi

make && gcc ptm.c -o ptm -L./ -lpcap && sudo ./ptm $IFACE
