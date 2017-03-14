#!/bin/bash

make && gcc ptm.c -o ptm -L./ -lpcap && sudo ./ptm
