# SURF2017
# File: DetectorOld.py
# Created: 7/27/17
# Author: Stephanie Ding

import FlowParser as fp
import subprocess
import os
import csv
import re
import numpy as np
import glob
from sklearn.externals import joblib

MODELS_FOLDER = "../models/"
FEATURES_LIST = fp.ARGUS_FIELDS

class Model:
    model = ''
    filename = ''
    features_list = ''

    hosts_prefix = ''
    botnet_hosts = {}
    botnet_dsts = {}

    def __init__(self, model_filename, features_list, hosts_prefix):
        self.filename = model_filename
        self.model = joblib.load(model_filename)
        self.features_list = features_list
        self.hosts_prefix = hosts_prefix

    def reset(self):
        for i in self.botnet_hosts:
            self.botnet_hosts[i] = 0

        for i in self.botnet_dsts:
            self.botnet_dsts[i] = 0

    def predict(self, flows, xs):
        self.reset()

        y_pred = self.model.predict(xs)
        for flow_id, y in zip(flows, y_pred):
            src, dst = fp.get_src_dst(flow_id)
            if y == 1 and src.startswith(self.hosts_prefix):
                if src not in self.botnet_hosts:
                    self.botnet_hosts[src] = 1
                else:
                    self.botnet_hosts[src] += 1

            if y == 1 and dst.startswith(self.hosts_prefix):
                if dst not in self.botnet_hosts:
                    self.botnet_hosts[dst] = 1
                else:
                    self.botnet_hosts[dst] += 1
            elif y == 1:
                if dst not in self.botnet_dsts:
                    self.botnet_dsts[dst] = 1
                else:
                    self.botnet_dsts[dst] += 1

    def get_botnet_hosts(self):
        return self.botnet_hosts

    def get_botnet_dsts(self):
        return self.botnet_dsts

class Session:
    owd = ''
    features_list = ''
    models = {}

    internal_hosts_prefix = ''
    capture_folder = ''
    window_id = 0

    model_reports = {}
    hosts_ranking = {}

    '''
    Constructor
    '''
    def __init__(self, models_folder, features_list, window_length, overlap_length, internal_hosts_prefix):
        self.owd = os.getcwd()

        self.window_length = window_length
        self.overlap_length = overlap_length
        self.internal_hosts_prefix = internal_hosts_prefix

        self.features_list = features_list
        self.load_models(models_folder)

    '''
    Loads all models in the folder
    '''
    def load_models(self, models_folder):
        print("Loading all models in: " + models_folder)
        model_id = 1
        os.chdir(models_folder)
        for model_fname in glob.glob("*.pkl"):
            print("+ " + model_fname)
            model = Model(model_fname, self.features_list, self.internal_hosts_prefix)
            self.models[model_id] = model
            self.model_reports[model_id] = {}
            model_id += 1
        print("Loaded " + str(model_id - 1) + " models")

    '''
    Begin online session (live capture from network interface)
    '''
    def begin_online(self):
        # TODO
        pass

    '''
    Captures a .pcap of window length and processes it
    '''
    def capture_pcap(self):
        self.prev_flows = self.current_flows
        self.prev_infected_hosts = self.curr_infected_hosts
        self.current_flows = set()
        self.curr_infected_hosts = set()
        self.capid += 1
        # do capture
        pass

    '''
    Begin offline session (from .pcap file)
    '''
    def begin_offline_from_file(self, pcap_file):
        # todo
        pass

    '''
    Begin offline session (with folder of binetflows)
    '''
    def begin_offline_from_folder(self, pcap_folder):
        print("\nBeginning offline session on folder: " + pcap_folder)

        self.window_id = 1
        os.chdir(pcap_folder)

        while True:
            # Get binetflow file
            current_fname = str(self.window_id) + ".binetflow"
            print(current_fname)

            # If is a valid file
            if os.path.isfile(current_fname):
                flows, xs = fp.parse_binetflow(current_fname, self.features_list)

                # Go through each of the models and run prediction, get output
                for model_id in range(1, len(self.models) + 1):
                    model = self.models[model_id]
                    model.predict(flows, xs)
                    botnet_hosts = model.get_botnet_hosts()

                    window_count = self.window_id - 1
                    for host in botnet_hosts:
                        if host not in self.model_reports[model_id]:
                            self.model_reports[model_id][host] = [0] * window_count + [botnet_hosts[host]]
                        else:
                            self.model_reports[model_id][host].append(botnet_hosts[host])


                self.window_id += 1
            else:
                break

        os.chdir(self.owd)

    '''
    Generate text-based report of all hosts and prediction time series associated with a particular model
    '''
    def generate_report(self, model_id, outfile):
        with open(outfile, "w") as f:
            f.write("model id: " + str(model_id) + "\t model filename: " + self.models[model_id].filename + "\n\n")
            hosts = sorted(self.model_reports[model_id].keys())
            for host in hosts:
                f.write(host + ",")
                f.write(",".join([str(x) for x in self.model_reports[model_id][host]]))
                f.write("\n")


def main():
    sess = Session(MODELS_FOLDER, FEATURES_LIST, 300, 150, "147.32")
    sess.begin_offline_from_folder("/media/SURF2017/CTU-13-Dataset/9/capture20110817pcaptruncated_300_150")
    sess.generate_report(6, "/media/SURF2017/CTU-13-Dataset/9/test_output.txt")

if __name__ == "__main__":
    main()
