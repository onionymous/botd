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

# make temporary directory
mkdir temp

# loop through all .pcaps in the directory
for file in *.pcap; do
	# make the rules file
	echo -n '<?xml version ="1.0" encoding="UTF-8"?>\n<!DOCTYPE RULESET SYSTEM "rulefile.dtd"> \n<RULESET ID="1">\n  <GLOBAL>\n    <ACTION NAME="netai_flowstats">\n      <PREF NAME="Idle_Threshold">1000000</PREF>\n    </ACTION>\n    <EXPORT NAME="ac_file">\n      <PREF NAME="Filename">' >> temp/rules.xml
	echo -n $PCAP_DIR >> temp/rules.xml
	echo -n \/ >> temp/rules.xml
	echo -n $(basename "$file" .pcap) >> temp/rules.xml
	echo -n '.csv' >> temp/rules.xml
	echo -n '</PREF>\n      <PREF NAME="FlowID">no</PREF>\n      <PREF NAME="ExportStatus">no</PREF>\n    </EXPORT>\n  </GLOBAL>\n  <RULE ID="1">\n    <!-- match all udp/tcp packets -->\n    <FILTER NAME="SrcIP">*</FILTER>\n    <FILTER NAME="SrcPort">*</FILTER>\n    <FILTER NAME="DstIP">*</FILTER>\n    <FILTER NAME="DstPort">*</FILTER>\n    <FILTER NAME="Proto">tcp,udp</FILTER>\n    <PREF NAME="auto">yes</PREF>\n    <PREF NAME="bidir">yes</PREF>\n    <PREF NAME="FlowTimeout">600</PREF>\n  </RULE>\n</RULESET>' >> temp/rules.xml

	# invoke netmate-flowcalc
	netmate -r temp/rules.xml -f "$file"

	# delete temporary file
	rm temp/rules.xml
done

rmdir temp