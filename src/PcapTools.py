# SURF2017
# File: PcapTools.py
# Created: 8/2/17
# Author: Stephanie Ding

# NOTE: REQUIRED DEPENDENCIES: Wireshark, editcap, argus

import FlowParser as fp
import subprocess
import os
import errno
import re
import glob
from datetime import date, datetime, timedelta

'''
Splits a .pcap file into time windows of <window_size> seconds with <overlap> seconds overlapping between windows
Files are output to a folder with the name of the original pcap and the split files are named <1...n>.pcap
The folder name is returned for further actions (e.g. generating all netflows in the folder)
'''
def generate_windowed_pcaps(filepath, window_size, overlap):
    print("Opening " + filepath + "...")

    # Get time of first and last packet using editcaps
    output = subprocess.check_output(['capinfos', '-u', '-a', '-e', filepath])
    r_first = re.compile("First packet time:\s*(.*)$", re.MULTILINE)
    r_last = re.compile("Last packet time:\s*(.*)$", re.MULTILINE)

    # Parse times into datetime objects
    dt_first = datetime.strptime(r_first.search(output).groups(1)[0], "%Y-%m-%d %H:%M:%S.%f")
    dt_last = datetime.strptime(r_last.search(output).groups(1)[0], "%Y-%m-%d %H:%M:%S.%f") + timedelta(seconds=1)

    # Get basepath of pcap file and create new output folder for the split pcaps
    dirname, basename = os.path.split(filepath)
    filename, ext = os.path.splitext(basename)
    output_folder = os.path.join(dirname, '_'.join([re.sub('[^0-9a-zA-Z]+', '', filename), str(window_size), str(overlap)]))

    try:
        os.makedirs(output_folder)
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

    # Generator for datetime ranges
    def daterange(start, end, delta):
        curr = start
        while curr < end:
            yield curr
            curr += delta

    # For each interval, filter the packets in that time
    for i, d in enumerate(daterange(dt_first, dt_last, timedelta(seconds=overlap)), 1):
        start_time = d.strftime("%Y-%m-%d %H:%M:%S")
        end_time = (d + timedelta(seconds=window_size)).strftime("%Y-%m-%d %H:%M:%S")
        #print(start_time, end_time)
        new_filename = os.path.join(output_folder, str(i)) + ext
        args = ['editcap', '-A', start_time, '-B', end_time, '-F', 'pcap', filepath, new_filename]
        cmd = subprocess.list2cmdline(args)
        print(cmd)
        subprocess.call(args)

    return output_folder

'''
Generates all Argus bidirectional netflows for all the pcaps in a specified folder
'''
def generate_argus_binetflows(folder_name):
    os.chdir(folder_name)
    for file in glob.glob("*.pcap"):
        filename, ext = os.path.splitext(file)
        argusfile = filename + '.argus'
        args = ['argus', '-r', file, '-w', argusfile, '-ARJZ']
        subprocess.call(args)

        binetflow_file = filename + '.binetflow'
        print(binetflow_file)
        outfile = open(binetflow_file, 'w')
        args = ['ra', '-n', '-u', '-r', argusfile, '-s', 'srcid', 'stime', 'ltime', 'flgs', 'seq', 'smac', 'dmac',
                'soui', 'doui', 'saddr', 'daddr', 'proto', 'sport', 'dport', 'stos', 'dtos', 'sdsb', 'ddsb', 'sco',
                'dco', 'sttl', 'dttl', 'sipid', 'dipid', 'smpls', 'dmpls', 'spkts', 'dpkts', 'sbytes', 'dbytes',
                'sappbytes', 'dappbytes', 'sload', 'dload', 'sloss', 'dloss', 'sgap', 'dgap', 'dir', 'sintpkt',
                'dintpkt', 'sintdist', 'dintdist', 'sintpktact', 'dintpktact', 'sintdistact', 'dintdistact',
                'sintpktidl', 'dintpktidl', 'sintdistidl', 'dintdistidl', 'sjit', 'djit', 'sjitact', 'djitact',
                'sjitidle', 'djitidle', 'state', 'suser', 'duser', 'swin', 'dwin', 'svlan', 'dvlan', 'svid', 'dvid',
                'svpri', 'dvpri', 'srng', 'erng', 'stcpb', 'dtcpb', 'tcprtt', 'synack', 'ackdat', 'tcpopt', 'inode',
                'offset', 'spktsz', 'dpktsz', 'smaxsz', 'dmaxsz', 'sminsz', 'dminsz', 'dur', 'rate', 'srate', 'drate',
                'trans', 'runtime', 'mean', 'stddev', 'sum', 'min', 'max', 'pkts', 'bytes', 'appbytes', 'load', 'loss',
                'ploss', 'sploss', 'dploss', 'abr', '-c', ',']
        #cmd = subprocess.list2cmdline(args)
        subprocess.call(args, stdout=outfile)
        outfile.close()