#!/bin/bash

# A small script to run netmate-flowcalc for all files in a directory and
# generate .csv files

# check that an argument is passed in i.e. the directory of .pcaps
if [ $# -eq 0 ]
	then
	echo "Usage: sudo ./calculate_flows.sh <DIRECTORY_OF_PCAPS>"
	exit 1
fi

# change directory to pcap directory
PCAP_DIR=$1
cd "$PCAP_DIR"

# loop through all .pcaps in the directory
for file in *.pcap; do
	FILENAME=$(basename "$file" .pcap)
	FILENAME+=".csv"

	# invoke netmate-flowcalc
	/home/orion/gocode/bin/flowtbag "$file" > "$FILENAME"
done