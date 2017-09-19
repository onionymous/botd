# SURF2017
# File: ccdetector
# Created: 8/6/17
# Author: Stephanie Ding

import csv
import FlowParser as fp

OUTPUT_CC_FLOWS = "/media/SURF2017/CTU-13-Dataset/all_cc_extended.txt"
OUTPUT_EXTENDED_CC = "/media/SURF2017/CTU-13-Dataset/all_cc_extended.txt"

def process(labelled, unlabelled, dataset_no):
    botnet_flows = set()
    normal_flows = set()
    cc_flows = set()

    print("Opening labelled Argus binetflow...")
    total = 0
    skipped = 0
    with open(labelled) as f:
        reader = csv.DictReader(f)
        for flow in reader:
            total += 1
            flow_id = fp.get_argus_flow_id(flow)

            if 'From-Botnet' in flow['Label']:
                if 'CC' in flow['Label']:
                    cc_flows.add(flow_id)
                else:
                    botnet_flows.add(flow_id)
            elif 'Normal' in flow['Label']:
                normal_flows.add(flow_id)
            elif 'Background' in flow['Label']:
                background_flows.add(flow_id)
            else:
                skipped += 1
                continue

def main():
    pass


if __name__ == "__main__":
    main()
