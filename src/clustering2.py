# SURF2017
# File: clustering.py
# Created: 7/10/17
# Author: Stephanie Ding

from __future__ import division

import FlowParser as fp
import subprocess
import os
import errno
import re
import glob
import numpy as np
from datetime import date, datetime, timedelta
from sklearn.manifold import TSNE
from sklearn.cluster import KMeans, MiniBatchKMeans, DBSCAN, AgglomerativeClustering
from sklearn import metrics
from sklearn import decomposition
from sklearn.externals import joblib
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
import constants

# Splits a .pcap file into time windows of <window_size> seconds with <overlap> seconds overlapping between windows
# Files are output to a folder with the name of the original pcap and the split files are named <1...n>.pcap
# The folder name is returned for further actions (e.g. generating all netflows in the folder)
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

# Generates all Argus bidirectional netflows for all the pcaps in a specified folder
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

# Outputs TSNE for all binetflow files in a folder
def batch_tsne(folder_name, infection_start, labelled):
    os.chdir(folder_name)

    try:
        os.makedirs('tsne')
    except OSError as e:
        if e.errno != errno.EEXIST:
            raise

    for file in glob.glob("*.binetflow"):
        filename, ext = os.path.splitext(file)
        infected = False if int(filename) < infection_start else True
        output_file = os.path.join(folder_name, 'tsne', filename) + '.png'
        generate_tsne(5000, infected, labelled, file, output_file)

def generate_tsne(num_flows, infected, labelled, unlabelled, output_file):
    #dataset_no = int(input("Enter the number for the dataset: "))
    #labelled = raw_input("Enter the filename for the labelled Argus binetflows: ")
    #unlabelled = raw_input("Enter the filename for the unlabelled Argus binetflows: ")

    flows, xs, ys = fp.parse_argus(labelled, unlabelled)

    tsne = TSNE(n_components=2, verbose=1, perplexity=40, n_iter=300)
    tsne_results = tsne.fit_transform(xs[:num_flows])

    x1 = []
    y1 = []

    x2 = []
    y2 = []

    if not infected:
        for i in range(num_flows):
            x1.append(tsne_results[i][0])
            y1.append(tsne_results[i][1])
    else:
        for i in range(num_flows):
            if ys[i] == 0:
                x1.append(tsne_results[i][0])
                y1.append(tsne_results[i][1])
            else:
                x2.append(tsne_results[i][0])
                y2.append(tsne_results[i][1])

    # Create plot
    plt.ioff()
    fig = plt.figure(figsize=(8, 8), dpi=100, facecolor='w', edgecolor='k')
    ax = fig.add_subplot(1, 1, 1)
    ax.set_autoscalex_on(False)
    ax.set_autoscaley_on(False)
    ax.set_xlim([-30, 30])
    ax.set_ylim([-30, 30])

    ax.scatter(x1, y1, alpha=0.8, c="blue", edgecolors='none', s=30, label="normal")
    ax.scatter(x2, y2, alpha=0.8, c="red", edgecolors='none', s=30, label="botnet")

    #plt.title("CTU-13 Dataset " + str(dataset_no) + " t-SNE")
    plt.legend(loc=2)
    fig.savefig(output_file, bbox_inches='tight')
    plt.close(fig)
    #plt.show()

def dbscan_old():
    nb_file = "/media/SURF2017/CTU-13-Dataset/9/capture20110817pcaptruncated_300_150/7.binetflow"
    b_file = "/media/SURF2017/CTU-13-Dataset/9/capture20110817pcaptruncated_300_150/86.binetflow"
    labels_file = "/media/SURF2017/CTU-13-Dataset/9/capture20110817.binetflow"

    features_list = raw_input("Enter space-separated list of features (or press enter to use default set of 40): ")

    try:
        if features_list != '':
            features_list = features_list.split()
        else:
            features_list = fp.ARGUS_FIELDS
    except Exception, e:
        features_list = fp.ARGUS_FIELDS

    print("Using features list: " + str(features_list))

    nb_flows, nb_xs, nb_ys = fp.parse_ctu(nb_file, labels_file, features_list)
    b_flows, b_xs, b_ys = fp.parse_ctu(b_file, labels_file, features_list)

    nb_xs = StandardScaler().fit_transform(nb_xs)
    b_xs =  StandardScaler().fit_transform(b_xs)

    print("Running PCA...")
    pca = decomposition.PCA()
    nb_xs_reduced = pca.fit_transform(nb_xs)
    print("Shape after PCA: " + str(nb_xs_reduced.shape()))

    nb_clusters = {}

    nb_db = DBSCAN(eps=0.3, min_samples=10, random_state=0).fit(nb_xs_reduced)
    nb_labels = nb_db.labels_

    for flow, label in zip(nb_flows, nb_labels):
        src, dst = fp.get_src_dst(flow)
        if label not in nb_labels:
            nb_clusters[label] = {src}
        else:
            nb_clusters[label].add(src)

    print(nb_clusters)

def inter_cluster_distance(data):
    tot = 0.

    for i in xrange(data.shape[0] - 1):
        tot += ((((data[i + 1:] - data[i]) ** 2).sum(1)) ** .5).sum()

    avg = tot / ((data.shape[0] - 1) * (data.shape[0]) / 2.)
    return avg

def dbscan(model_file, binetflow_file):
    clf = joblib.load(model_file)

    flows, xs = fp.parse_binetflow(binetflow_file)
    y_pred = clf.predict(xs)

    new_flows = []
    new_xs = []

    total = 0

    botnet_hosts = {}
    for flow, x, y in zip(flows, xs, y_pred):
        if y == 1:
            total += 1
            #new_flows.append(flow)
            #new_xs.append(x)
            #new_xs.append([x[0], x[1], x[2], x[3], x[4], x[5], x[20], x[21], x[22], x[23]])
            src, dst = fp.get_src_dst(flow)
            if src.startswith("147.32"):
                if src not in botnet_hosts:
                    botnet_hosts[src] = {}
                    botnet_hosts[src]['count'] = 1
                    botnet_hosts[src]['srcpkts'] = x[2]
                    botnet_hosts[src]['dstpkts'] = x[3]
                    botnet_hosts[src]['srcbytes'] = x[4]
                    botnet_hosts[src]['dstbytes'] = x[5]
                    botnet_hosts[src]['unique_ports'] = set([flow[3]])
                    botnet_hosts[src]['unique_dsts'] = set([dst])
                else:
                    botnet_hosts[src]['count'] += 1
                    botnet_hosts[src]['srcpkts'] += x[2]
                    botnet_hosts[src]['dstpkts'] += x[3]
                    botnet_hosts[src]['srcbytes'] += x[4]
                    botnet_hosts[src]['dstbytes'] += x[5]
                    botnet_hosts[src]['unique_ports'].add(flow[3])
                    botnet_hosts[src]['unique_dsts'].add(dst)
            if dst.startswith("147.32"):
                if dst not in botnet_hosts:
                    botnet_hosts[dst] = {}
                    botnet_hosts[dst]['count'] = 1
                    botnet_hosts[dst]['srcpkts'] = x[3]
                    botnet_hosts[dst]['dstpkts'] = x[2]
                    botnet_hosts[dst]['srcbytes'] = x[5]
                    botnet_hosts[dst]['dstbytes'] = x[4]
                    botnet_hosts[dst]['unique_ports'] = set([flow[1]])
                    botnet_hosts[dst]['unique_dsts'] = set([src])
                else:
                    botnet_hosts[dst]['count'] += 1
                    botnet_hosts[dst]['srcpkts'] += x[3]
                    botnet_hosts[dst]['dstpkts'] += x[2]
                    botnet_hosts[dst]['srcbytes'] += x[5]
                    botnet_hosts[dst]['dstbytes'] += x[4]
                    botnet_hosts[dst]['unique_ports'].add(flow[1])
                    botnet_hosts[dst]['unique_dsts'].add(src)

    ips = []
    new_xs = []

    for host in botnet_hosts:
        ips.append(host)
        curr = botnet_hosts[host]
        new_xs.append([curr['count'], curr['srcpkts'], curr['dstpkts'], curr['srcbytes'], curr['dstbytes'], len(curr['unique_ports'])/65535, len(curr['unique_dsts'])])

    # tsne = TSNE(n_components=2, verbose=1, perplexity=10, n_iter=300)
    # tsne_results = tsne.fit_transform(new_xs)
    scaled_xs = StandardScaler().fit_transform(new_xs)

    # db = DBSCAN(eps=0.3, min_samples=10).fit(scaled_xs)
    # db = DBSCAN(eps=0.3, min_samples=1).fit(scaled_xs)

    labels = db.labels_
    # core_samples_mask = np.zeros_like(db.labels_, dtype=bool)
    # core_samples_mask[db.core_sample_indices_] = True
    # n_clusters_ = len(set(labels)) - (1 if -1 in labels else 0)

    clusters = {}

    # for flow_id, x, label in zip(new_flows, scaled_xs, labels):
    #     src, dst = fp.get_src_dst(flow_id)
    #     #print(src, dst, label)
    #     if label not in clusters:
    #         clusters[label] = {}
    #         clusters[label]['flows'] = [x]
    #         clusters[label]['count'] = 1
    #         clusters[label]['ips'] = set([src])
    #     else:
    #         clusters[label]['flows'].append(x)
    #         clusters[label]['count'] += 1
    #         clusters[label]['ips'].add(src)

    # for id, cluster in sorted(clusters.items(), key=lambda x: x[1]['count'], reverse=True):
    #     dist = inter_cluster_distance(np.array(cluster['flows']))
    #     print("cluster: " + str(id) + " length: " + str(cluster['count']) + " dist: " + str(dist/cluster['count']))
    #     for i in cluster['ips']:
    #         print(i)
    #     print('\n')


    # Black removed and is used for noise instead.
    # unique_labels = set(labels)
    # colors = [plt.cm.Spectral(each)
    #           for each in np.linspace(0, 1, len(unique_labels))]
    # for k, col in zip(unique_labels, colors):
    #     if k == -1:
    #         # Black used for noise.
    #         col = [0, 0, 0, 1]
    #
    #     class_member_mask = (labels == k)
    #
    #     xy = tsne_results[class_member_mask & core_samples_mask]
    #     plt.plot(xy[:, 0], xy[:, 1], 'o', markerfacecolor=tuple(col),
    #              markeredgecolor='k', markersize=6)
    #
    #     xy = tsne_results[class_member_mask & ~core_samples_mask]
    #     plt.plot(xy[:, 0], xy[:, 1], 'o', markerfacecolor=tuple(col),
    #              markeredgecolor='k', markersize=2)
    #
    # plt.title('Estimated number of clusters: %d' % n_clusters_)
    # plt.show()

def agglomerative_clustering(model_file, binetflow_folder, outfile):
    f = open(outfile, "w")
    clf = joblib.load(model_file)

    os.chdir(binetflow_folder)
    for i in range(1, 393):
        filename = str(i) + ".binetflow"
        f.write("current window: " + filename + "\n")
        flows, xs = fp.parse_binetflow(filename)
        y_pred = clf.predict(xs)

        total = 0

        botnet_hosts = {}
        for flow, x, y in zip(flows, xs, y_pred):
            if y == 1:
                total += 1
                src, dst = fp.get_src_dst(flow)
                if src.startswith("147.32"):
                    if src not in botnet_hosts:
                        botnet_hosts[src] = {}
                        botnet_hosts[src]['count'] = 1
                        botnet_hosts[src]['srcpkts'] = x[2]
                        botnet_hosts[src]['dstpkts'] = x[3]
                        botnet_hosts[src]['srcbytes'] = x[4]
                        botnet_hosts[src]['dstbytes'] = x[5]
                        botnet_hosts[src]['unique_ports'] = set([flow[3]])
                        botnet_hosts[src]['unique_dsts'] = set([dst])
                    else:
                        botnet_hosts[src]['count'] += 1
                        botnet_hosts[src]['srcpkts'] += x[2]
                        botnet_hosts[src]['dstpkts'] += x[3]
                        botnet_hosts[src]['srcbytes'] += x[4]
                        botnet_hosts[src]['dstbytes'] += x[5]
                        botnet_hosts[src]['unique_ports'].add(flow[3])
                        botnet_hosts[src]['unique_dsts'].add(dst)
                if dst.startswith("147.32"):
                    if dst not in botnet_hosts:
                        botnet_hosts[dst] = {}
                        botnet_hosts[dst]['count'] = 1
                        botnet_hosts[dst]['srcpkts'] = x[3]
                        botnet_hosts[dst]['dstpkts'] = x[2]
                        botnet_hosts[dst]['srcbytes'] = x[5]
                        botnet_hosts[dst]['dstbytes'] = x[4]
                        botnet_hosts[dst]['unique_ports'] = set([flow[1]])
                        botnet_hosts[dst]['unique_dsts'] = set([src])
                    else:
                        botnet_hosts[dst]['count'] += 1
                        botnet_hosts[dst]['srcpkts'] += x[3]
                        botnet_hosts[dst]['dstpkts'] += x[2]
                        botnet_hosts[dst]['srcbytes'] += x[5]
                        botnet_hosts[dst]['dstbytes'] += x[4]
                        botnet_hosts[dst]['unique_ports'].add(flow[1])
                        botnet_hosts[dst]['unique_dsts'].add(src)

        ips = []
        new_xs = []

        for host in botnet_hosts:
            ips.append(host)
            curr = botnet_hosts[host]
            new_xs.append([curr['count'], curr['srcpkts'], curr['dstpkts'], curr['srcbytes'], curr['dstbytes'],
                           len(curr['unique_ports']) / 65535, len(curr['unique_dsts'])])


        scaled_xs = StandardScaler().fit_transform(new_xs)
        db = AgglomerativeClustering().fit(scaled_xs)

        labels = db.labels_

        clusters = {}
        host_vectors = {}

        for host, x, label in zip(ips, scaled_xs, labels):
            if label not in clusters:
                clusters[label] = set([host])
                host_vectors[label] = [x]
            else:
                clusters[label].add(host)

        for i in sorted(clusters.keys()):
            f.write("cluster: " + str(i) + " num IPs: " + str(len(clusters[i])) + " var: " + str(np.var(host_vectors[i])) + "\n")
            f.write(", ".join(clusters[i]) + "\n")

        f.write("\n")

    f.close()

def agglomerative_clustering2(models_folder, binetflow_folder, outfile):
    models = []
    f = open(outfile, "w")
    os.chdir(models_folder)
    for model_fname in glob.glob("*.pkl"):
        clf = joblib.load(model_fname)
        models.append(clf)

    os.chdir(binetflow_folder)
    for window in range(1, 393):
        filename = str(window) + ".binetflow"
        # f.write("current window: " + filename + "\n")
        print("current window: " + filename)
        flows, xs = fp.parse_binetflow(filename)

        botnet_flows = []
        botnet_xs = []
        total = 0

        ys = []

        for clf in models:
            y_pred = clf.predict(xs)
            ys.append(y_pred)

        i = 0
        for flow, x in zip(flows, xs):
            for y in ys:
                if y[i] == 1:
                    botnet_flows.append(flow)
                    botnet_xs.append(x)
                    break
            i += 1

        botnet_hosts = {}
        for flow, x in zip(botnet_flows, botnet_xs):
            src, dst = fp.get_src_dst(flow)
            if src.startswith("147.32"):
                if src not in botnet_hosts:
                    botnet_hosts[src] = {}
                    botnet_hosts[src]['count'] = 1
                    botnet_hosts[src]['srcpkts'] = x[2]
                    botnet_hosts[src]['dstpkts'] = x[3]
                    botnet_hosts[src]['srcbytes'] = x[4]
                    botnet_hosts[src]['dstbytes'] = x[5]
                    botnet_hosts[src]['unique_ports'] = set([flow[3]])
                    botnet_hosts[src]['unique_dsts'] = set([dst])
                else:
                    botnet_hosts[src]['count'] += 1
                    botnet_hosts[src]['srcpkts'] += x[2]
                    botnet_hosts[src]['dstpkts'] += x[3]
                    botnet_hosts[src]['srcbytes'] += x[4]
                    botnet_hosts[src]['dstbytes'] += x[5]
                    botnet_hosts[src]['unique_ports'].add(flow[3])
                    botnet_hosts[src]['unique_dsts'].add(dst)
            if dst.startswith("147.32"):
                if dst not in botnet_hosts:
                    botnet_hosts[dst] = {}
                    botnet_hosts[dst]['count'] = 1
                    botnet_hosts[dst]['srcpkts'] = x[3]
                    botnet_hosts[dst]['dstpkts'] = x[2]
                    botnet_hosts[dst]['srcbytes'] = x[5]
                    botnet_hosts[dst]['dstbytes'] = x[4]
                    botnet_hosts[dst]['unique_ports'] = set([flow[1]])
                    botnet_hosts[dst]['unique_dsts'] = set([src])
                else:
                    botnet_hosts[dst]['count'] += 1
                    botnet_hosts[dst]['srcpkts'] += x[3]
                    botnet_hosts[dst]['dstpkts'] += x[2]
                    botnet_hosts[dst]['srcbytes'] += x[5]
                    botnet_hosts[dst]['dstbytes'] += x[4]
                    botnet_hosts[dst]['unique_ports'].add(flow[1])
                    botnet_hosts[dst]['unique_dsts'].add(src)

        ips = []
        new_xs = []

        for host in botnet_hosts:
            ips.append(host)
            curr = botnet_hosts[host]
            new_xs.append([curr['count'], curr['srcpkts'], curr['dstpkts'], curr['srcbytes'], curr['dstbytes'],
                           len(curr['unique_ports']) / 65535, len(curr['unique_dsts'])])


        scaled_xs = StandardScaler().fit_transform(new_xs)
        db = AgglomerativeClustering().fit(scaled_xs)

        labels = db.labels_

        clusters = {}
        host_vectors = {}

        for host, x, label in zip(ips, scaled_xs, labels):
            if label not in clusters:
                clusters[label] = set([host])
                host_vectors[label] = [x]
            else:
                clusters[label].add(host)
                host_vectors[label].append(x)

        var_benign = np.var(host_vectors[0])
        var_bots = np.var(host_vectors[1])
        if var_benign > var_bots:
            clusters = {0: clusters[1], 1: clusters[0]}
            var_benign, var_bots = var_bots, var_benign

        f.write(",".join([str(v) for v in [window, var_benign, len(clusters[0]), var_bots, len(clusters[1])] ]))

        # for i in sorted(clusters.keys()):
        #     f.write("cluster: " + str(i) + " num IPs: " + str(len(clusters[i])) + " var: " + str(np.var(host_vectors[i])) + "\n")
        #     f.write(", ".join(clusters[i]) + "\n")

        f.write("\n")

    f.close()

def evaluate_clustering(cluster_output, actual_infected_ips):
    print("window,n_infected,tp,fp,fn,tpr,fpr,fnr")
    with open(cluster_output) as f:
        while True:
            window_line = f.readline().strip("\n")
            cluster1_info = f.readline()
            if not cluster1_info:
                break
            cluster1_line = f.readline().strip("\n")
            cluster2_info = f.readline().strip("\n")
            cluster2_line = f.readline().strip("\n")

            window = window_line.lstrip("current window: ").rstrip(".binetflow")
            cluster0 = set(cluster1_line.split(", "))
            cluster1 = set(cluster2_line.split(", "))

            if len(cluster0) < len(cluster1):
                cluster0, cluster1 = cluster1, cluster0

            fp = 0
            tp = 0
            fn = 0

            for i in actual_infected_ips:
                if i not in cluster1:
                    fn += 1

            for i in cluster1:
                if i in actual_infected_ips:
                    tp += 1
                else:
                    fp += 1

            fpr = fp / len(actual_infected_ips)
            tpr = tp / len(actual_infected_ips)
            fnr = fn / len(actual_infected_ips)

            print(",".join([window,str(len(actual_infected_ips)),str(tp),str(fp),str(fn),str(tpr),str(fpr),str(fnr)]))

            newline = f.readline()


def main():
    #
# evaluate_clustering("/media/SURF2017/CTU-13-Dataset/11/clustering_output.txt", constants.DATASET_11_INFECTED_HOSTS)
    OUTFILE = "/media/SURF2017/clustering_output_12_AC.txt"
    # MODEL = "/media/SURF2017/SURF2017/models/ctu9_40_300_gb.pkl"
    MODEL_FOLDER = "/media/SURF2017/SURF2017/models/"
    #dbscan(MODEL, "/media/SURF2017/CTU-13-Dataset/9/capture20110817pcaptruncated_300_150/3.binetflow")
    #agglomerative_clustering(MODEL, "/media/SURF2017/CTU-13-Dataset/9/capture20110817pcaptruncated_300_150", OUTFILE)
    agglomerative_clustering2(MODEL_FOLDER, "/media/SURF2017/SURF2017/datasets/CTU-13-Dataset/12/capture20110819truncated_300_150", OUTFILE)
    # pcap_file = raw_input("Enter the .pcap file: ")
    # labelled_file = raw_input("Enter the labelled file: ")az
    # output_folder = generate_windowed_pcaps(pcap_file, 300, 150)
    # generate_argus_binetflows(output_folder)
    #batch_tsne('/media/SURF2017/CTU-13-Dataset/9/capture20110817pcaptruncated_300_150/', 56, '/media/SURF2017/CTU-13-Dataset/9/capture20110817.binetflow')


if __name__ == "__main__":
    main()
