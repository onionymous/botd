# SURF2017
# File: NetFlowSession.py
# Created: 6/23/17
# Author: Stephanie Ding

import constants
import settings
from datetime import datetime, timedelta

errors = 0
all_flows = {}
time_differences = {}

with open(settings.NETFLOW_FILENAME, 'r') as netflow_file:
    # aggregate flows
    header = netflow_file.readline().strip().split(',')
    for line in netflow_file:
        # parse the comma-separated line
        _start_time, _dur, proto, src_addr, _src_port, _direction, dst_addr, _dst_port, _state, _s_tos, _d_tos, _tot_pkts, _tot_bytes, _src_bytes, label = line.strip().split(',')

        # we only care about tcp and udp packets so far, ignore the icmp
        if proto not in {"tcp", "udp"}:
            continue

        try:
            # make the 5-tuple entry
            src_port = int(_src_port)
            dst_port = int(_dst_port)
            tup = (src_addr, src_port, dst_addr, dst_port, proto)

            # get the flow statistics
            tot_pkts = int(_tot_pkts)
            tot_bytes = int(_tot_bytes)
            dur = float(_dur)

            # get start and end time of flow
            start_time = datetime.strptime(_start_time, '%Y/%m/%d %H:%M:%S.%f')
            dur_secs, dur_microsecs = [int(i) for i in _dur.split('.')]
            end_time = start_time + timedelta(seconds=dur_secs, microseconds=dur_microsecs)

            flow = (start_time, end_time, dur, tot_pkts, tot_bytes)

            if tup not in all_flows:
                all_flows[tup] = {flow}
            else:
                all_flows[tup].add(flow)

        except Exception, e:
            # some parse error occured
            errors += 1
            continue

print("[-] Error parsing " + str(errors) + " lines")
print("[+] Unique source/destination pairs: " + str(len(all_flows)))

# process the aggregated flows by removing all source/destination pairs with only one flow
# sort all the aggregated flows by start time
processed_flows = {k: sorted(v, key=lambda x: x[0]) for k, v in all_flows.iteritems() if len(v) > 1}
print("[+] After removing all pairs that only have one flow: " + str(len(processed_flows)))
# print(processed_flows.values()[0])

i = 0 #DEBUGGING REMOVE LATER
for tup in processed_flows:
    if i > 10: # DEBUGGING REMOVE LATER
        break #DEBUGGING REMOVE LATER

    # merge overlapping intervals
    merged_times = []
    t_prev = (processed_flows[tup][0][0], processed_flows[tup][0][1])
    for (start_time, end_time, _, _, _) in processed_flows[tup][1:]:
        if t_prev[1] >= start_time:
            t_prev = (min(t_prev[0], start_time), max(t_prev[1], end_time))
        else:
            merged_times.append(t_prev)
            t_prev = (start_time, end_time)
    else:
        merged_times.append(t_prev)

    # find nyquist rate by taking 1/2 the minimum time interval between flows
    nyquist_rate = 0
    for t1, t2 in zip(*[iter(merged_times)]*2):
        tdelta = t2[0] - t1[1]
        if nyquist_rate == 0:
            nyquist_rate = tdelta
        else:
            nyquist_rate = min(nyquist_rate, tdelta)

    # if nyquist rate is 0, flow is constant 1, fft is dirac delta function
    if nyquist_rate == 0:
        processed_flows[tup].append(0) # flow is constant 1
        continue

    # otherwise, compute the fft, sampling at half the nyquist frequency
    # TODO

    print(len(merged_times), nyquist_rate)

    i += 1 # DEBUGGING REMOVE LATER


