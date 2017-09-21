# SURF2017
# File: Detector.py
# Created: 8/2/17
# Author: Stephanie Ding
# Description:
# GUI for the Detector app

from __future__ import division
import sys
import FlowParser as fp
import re
import os
import glob
import errno
import subprocess
import threading
import time
from datetime import date, datetime, timedelta
import pyqtgraph as pg
from PyQt4 import QtGui, QtCore
from sklearn.externals import joblib
from sklearn.cluster import AgglomerativeClustering
from sklearn.preprocessing import StandardScaler

MODELS_FOLDER = "../models/"
FEATURES_LIST = fp.ARGUS_FIELDS

OFFLINE_FOLDER = 0
OFFLINE_PCAP = 1
ONLINE = 2

ALPHA = 0.2

'''
Prevent garbage collecting so things don't go out of scope
'''
class WindowContainer(object):
    def __init__(self):
        self.window_list = []

    def add_new_window(self, window):
        self.window_list.append(window)

class Model:
    model = ''
    filename = ''
    features_list = ''

    hosts_prefix = ''

    total_botnet = 0

    botnet_flows = set()
    botnet_flows_count = {}

    def __init__(self, model_filename, features_list, hosts_prefix):
        self.filename = model_filename
        self.model = joblib.load(model_filename)
        self.features_list = features_list
        self.hosts_prefix = hosts_prefix

    def reset(self):
        self.total_botnet = 0
        self.botnet_flows = set()

        for i in self.botnet_flows_count:
            self.botnet_flows_count[i] = 0

    def predict(self, flows, xs):
        self.reset()

        y_pred = self.model.predict(xs)

        for flow, x, y in zip(flows, xs, y_pred):
            if y == 1:
                self.total_botnet += 1
                self.botnet_flows.add((flow, tuple(x)))
                src, dst = fp.get_src_dst(flow)

                if src.startswith(self.hosts_prefix):
                    if src not in self.botnet_flows_count:
                        self.botnet_flows_count[src] = 1
                    else:
                        self.botnet_flows_count[src] += 1

                if dst.startswith(self.hosts_prefix):
                    if dst not in self.botnet_flows_count:
                        self.botnet_flows_count[dst] = 1
                    else:
                        self.botnet_flows_count[dst] += 1

    '''
    Returns a per-host based count of how many predicted botnet flows associated with it
    '''
    def get_botnet_flows_count(self):
        return self.botnet_flows_count

    def get_botnet_flows(self):
        return self.botnet_flows


'''
Launcher window that asks user if they want to perform real-time .pcap capture or process from file.
'''


class Launcher(QtGui.QWidget):
    def __init__(self, window_container):
        super(Launcher, self).__init__()
        self.wc = window_container
        self.initUI()

    def initUI(self):
        self.setGeometry(300, 300, 250, 150)
        self.setWindowTitle('Launcher')
        self.setWindowIcon(QtGui.QIcon('../etc/favicon.png'))

        # Online mode not implemented!
        self.online_btn = QtGui.QPushButton('Online mode', self)
        self.online_btn.setEnabled(False)

        self.offline_btn = QtGui.QPushButton('Offline mode', self)
        self.offline_btn.resize(self.offline_btn.sizeHint())
        self.offline_btn.clicked.connect(self.offline_btn_handler)

        self.label = QtGui.QLabel("botd v1.0 (beta)")
        newfont = QtGui.QFont("Courier", 16, QtGui.QFont.Bold)
        newfont.setStyleHint(QtGui.QFont.TypeWriter)
        self.label.setFont(newfont)

        self.vbox = QtGui.QVBoxLayout()
        self.vbox.addWidget(self.label)
        self.vbox.addWidget(self.online_btn)
        self.vbox.addWidget(self.offline_btn)

        self.setLayout(self.vbox)

        self.center()
        self.show()

    def center(self):
        qr = self.frameGeometry()
        cp = QtGui.QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def offline_btn_handler(self):
        # TODO: change to adjustable
        window_length = 300
        overlap_length = 150
        internal_hosts_prefix = "147.32"

        self.dialog = QtGui.QFileDialog(self)
        self.dialog.setAcceptMode(QtGui.QFileDialog.AcceptOpen)
        self.dialog.setFileMode(QtGui.QFileDialog.ExistingFile)

        filepath = str(self.dialog.getOpenFileName(self, "Open .pcap", "../datasets/",
                                                   "Packet captures (*.pcap *.pcapng);;All files (*.*)"))

        if filepath != '':
            if (filepath.endswith('.pcap') or filepath.endswith('.pcapng')):
                dirname, basename = os.path.split(filepath)
                filename, ext = os.path.splitext(basename)
                output_folder = os.path.join(dirname, '_'.join(
                    [re.sub('[^0-9a-zA-Z]+', '', filename), str(window_length), str(overlap_length)]))
                print(output_folder)

                try:
                    main_app = MainApplication(filepath, output_folder, window_length, overlap_length, internal_hosts_prefix)
                    self.wc.add_new_window(main_app)
                    # main_app = (output_folder)
                except Exception as e:
                    print(e.message)
                self.close()
            else:
                msgbox = QtGui.QMessageBox()
                msgbox.setText("Error")
                msgbox.setInformativeText("Invalid .pcap file: " + filepath)
                msgbox.addButton(QtGui.QMessageBox.Ok)
                msgbox.exec_()


'''
Thread for making .argus and then Netflow files in intervals
'''
class NetflowThread(pg.QtCore.QThread):
    owd = ''
    pcap_file = ''

    statusinfo_signal = pg.QtCore.Signal(str)

    def __init__(self, pcap_file, window_size, overlap):
        super(NetflowThread, self).__init__()
        self.owd = os.getcwd()

        self.filepath = pcap_file
        self.window_size = window_size
        self.overlap = overlap

    def run(self):
        # Get basepath of pcap file and create new output folder for the split pcaps
        dirname, basename = os.path.split(self.filepath)
        filename, ext = os.path.splitext(basename)
        # output_folder = os.path.join(dirname,
        #                             '_'.join([re.sub('[^0-9a-zA-Z]+', '', filename), str(self.window_size), str(self.overlap)]))

        output_folder = os.path.join('_'.join([re.sub('[^0-9a-zA-Z]+', '', filename), str(self.window_size), str(self.overlap)]))

        if os.path.isdir(os.path.join(dirname, output_folder)):
            self.statusinfo_signal.emit(output_folder + " already exists. Skipping Netflow generation...")
            self.statusinfo_signal.emit("[PERM]Using existing folder")
            self.exit()

        os.chdir(dirname)

        # Get time of first and last packet using editcaps
        print("\nPreparing to generate NetFlows, running capinfos...")
        output = subprocess.check_output(['capinfos', '-u', '-a', '-e', self.filepath])
        r_first = re.compile("First packet time:\s*(.*)$", re.MULTILINE)
        r_last = re.compile("Last packet time:\s*(.*)$", re.MULTILINE)

        # Parse times into datetime objects
        dt_first = datetime.strptime(r_first.search(output).groups(1)[0], "%Y-%m-%d %H:%M:%S.%f")
        dt_last = datetime.strptime(r_last.search(output).groups(1)[0], "%Y-%m-%d %H:%M:%S.%f") + timedelta(seconds=1)

        try:
            os.makedirs(output_folder)
            os.chdir(output_folder)
            self.statusinfo_signal.emit("Created folder: " + output_folder)

            # Generator for datetime ranges
            def daterange(start, end, delta):
                curr = start
                while curr < end:
                    yield curr
                    curr += delta

            print("\nStarting to generate NetFlow files...")

            # For each interval, filter the packets in that time
            for i, d in enumerate(daterange(dt_first, dt_last, timedelta(seconds=self.overlap)), 1):
                # make the pcap
                start_time = d.strftime("%Y-%m-%d %H:%M:%S")
                end_time = (d + timedelta(seconds=self.window_size)).strftime("%Y-%m-%d %H:%M:%S")
                # print(start_time, end_time)
                # new_filename = os.path.join(output_folder, str(i)) + ext
                new_filename = str(i) + ext
                args = ['editcap', '-A', start_time, '-B', end_time, '-F', 'pcap', self.filepath, new_filename]
                cmd = subprocess.list2cmdline(args)
                print("Running: " + cmd)
                self.statusinfo_signal.emit("Running: " + cmd)
                subprocess.call(args)

                # Generate .argus
                argusfile = str(i) + '.argus'
                args = ['argus', '-r', new_filename, '-w', argusfile, '-ARJZ']
                cmd = subprocess.list2cmdline(args)
                print("Running: " + cmd)
                self.statusinfo_signal.emit("Running: " + cmd)
                subprocess.call(args)

                # Generate binetflow
                binetflow_file = str(i) + '.binetflow'
                self.statusinfo_signal.emit("Generating: " + binetflow_file)
                outfile = open(binetflow_file, 'w')
                args = ['ra', '-n', '-u', '-r', argusfile, '-s', 'srcid', 'stime', 'ltime', 'flgs', 'seq', 'smac',
                        'dmac',
                        'soui', 'doui', 'saddr', 'daddr', 'proto', 'sport', 'dport', 'stos', 'dtos', 'sdsb', 'ddsb',
                        'sco',
                        'dco', 'sttl', 'dttl', 'sipid', 'dipid', 'smpls', 'dmpls', 'spkts', 'dpkts', 'sbytes', 'dbytes',
                        'sappbytes', 'dappbytes', 'sload', 'dload', 'sloss', 'dloss', 'sgap', 'dgap', 'dir', 'sintpkt',
                        'dintpkt', 'sintdist', 'dintdist', 'sintpktact', 'dintpktact', 'sintdistact', 'dintdistact',
                        'sintpktidl', 'dintpktidl', 'sintdistidl', 'dintdistidl', 'sjit', 'djit', 'sjitact', 'djitact',
                        'sjitidle', 'djitidle', 'state', 'suser', 'duser', 'swin', 'dwin', 'svlan', 'dvlan', 'svid',
                        'dvid',
                        'svpri', 'dvpri', 'srng', 'erng', 'stcpb', 'dtcpb', 'tcprtt', 'synack', 'ackdat', 'tcpopt',
                        'inode',
                        'offset', 'spktsz', 'dpktsz', 'smaxsz', 'dmaxsz', 'sminsz', 'dminsz', 'dur', 'rate', 'srate',
                        'drate',
                        'trans', 'runtime', 'mean', 'stddev', 'sum', 'min', 'max', 'pkts', 'bytes', 'appbytes', 'load',
                        'loss',
                        'ploss', 'sploss', 'dploss', 'abr', '-c', ',']
                # cmd = subprocess.list2cmdline(args)
                subprocess.call(args, stdout=outfile)
                outfile.close()
        except OSError as e:
            if e.errno != errno.EEXIST:
                self.statusinfo_signal.emit(output_folder + " already exists. Skipping Netflow generation...")
                self.statusinfo_signal.emit("[PERM]Using existing folder")
                self.exit()

        os.chdir(self.owd)

'''
Thread for background processing of stuff
'''
class WorkerThread(pg.QtCore.QThread):
    owd = ''
    features_list = ''
    models_folder = ''

    models = {}

    internal_hosts_prefix = ''
    capture_folder = ''
    window_id = 0

    data = {}
    hosts_ranking = {}

    statusinfo_signal = pg.QtCore.Signal(str)

    models_loaded_signal = pg.QtCore.Signal(object)
    hosts_updated_signal = pg.QtCore.Signal(object)
    data_signal = pg.QtCore.Signal(object)

    mode = 0
    offline_folder = ''
    offline_pcap = ''
    network_interface = ''

    def __init__(self, models_folder, features_list, window_length, overlap_length, internal_hosts_prefix):
        super(WorkerThread, self).__init__()
        self.stop_mutex = threading.Lock()
        self._stop = False

        self.owd = os.getcwd()

        self.window_length = window_length
        self.overlap_length = overlap_length
        self.internal_hosts_prefix = internal_hosts_prefix

        self.models_folder = models_folder
        self.features_list = features_list

    '''
    Loads all models in the folder
    '''

    def load_models(self, models_folder):
        model_names = []

        print("Loading all models in: " + os.getcwd() + "/" + models_folder)
        self.statusinfo_signal.emit("Loading all models in: " + models_folder)
        model_id = 1
        os.chdir(models_folder)
        for model_fname in glob.glob("*.pkl"):
            model_names.append(str(model_id) + ": " + model_fname)

            print("+ " + model_fname)
            self.statusinfo_signal.emit("+ " + model_fname)
            model = Model(model_fname, self.features_list, self.internal_hosts_prefix)
            self.models[model_id] = model
            self.data[model_id] = {}
            model_id += 1
        print("Loaded " + str(model_id - 1) + " models")
        self.statusinfo_signal.emit("Loaded " + str(model_id - 1) + " models")
        os.chdir(self.owd)

        self.models_loaded_signal.emit(tuple(model_names))

    '''
    Set session mode
    '''

    def set_mode(self, mode, pcap_folder='', pcap_file='', network_interface=''):
        self.mode = mode
        self.pcap_folder = pcap_folder
        self.pcap_file = pcap_file
        self.network_interface = network_interface

    '''
    Thread main loop
    '''

    def run(self):
        self.load_models(self.models_folder)

        # If running in offline + folder mode
        if self.mode == OFFLINE_FOLDER:
            assert (self.pcap_folder != '')  # make sure pcap folder is not uninitialised

            print("\nBeginning offline session on folder: " + self.pcap_folder)
            self.statusinfo_signal.emit("Beginning offline session on folder: " + self.pcap_folder)

            self.window_id = 1

            # wait for other thread
            while True:
                try:
                    os.chdir(self.pcap_folder)
                    break
                except Exception as e:
                    self.statusinfo_signal.emit("Netflow folder not found. Preparing to generate windowed Netflow files by running capinfos (this may take a long time)...")
                    time.sleep(5)

            while True:
                # Must protect self._stop with a mutex because the main thread
                # might try to access it at the same time.
                with self.stop_mutex:
                    if self._stop:
                        # causes run() to exit, which kills the thread.
                        break

                    current_fname = str(self.window_id) + ".binetflow"
                    # print(current_fname)
                    self.statusinfo_signal.emit("Processing: " + current_fname)

                    # If is a valid file
                    if os.path.isfile(current_fname):
                        # Get the feature vectors and build data array
                        flows, xs = fp.parse_binetflow(current_fname, self.features_list)

                        # Go through each of the models and run prediction, get output
                        botnet_flows = set()

                        for model_id in range(1, len(self.models) + 1):
                            window_count = self.window_id - 1

                            model = self.models[model_id]
                            model.predict(flows, xs)
                            botnet_flows |= model.get_botnet_flows()      # add new flow IDs to suspicious
                            botnet_flows_count = model.get_botnet_flows_count()

                            for host in botnet_flows_count:
                                # Add to the time series
                                if host not in self.data[model_id]:
                                    self.data[model_id][host] = {}
                                    self.data[model_id][host]['avg'] = botnet_flows_count[host]
                                    self.data[model_id][host]['series'] = [0] * window_count + [
                                        botnet_flows_count[host]]
                                else:
                                    self.data[model_id][host]['series'].append(botnet_flows_count[host])

                                    # Exponential smoothing
                                    # t_prev = self.data[model_id][host]['series'][-1]
                                    # t_now = botnet_flows_count[host]
                                    # self.data[model_id][host]['series'].append(ALPHA * t_now + (1 - ALPHA) * t_prev)

                                    # Update the average
                                    old_avg = self.data[model_id][host]['avg']
                                    self.data[model_id][host]['avg'] = (old_avg * (window_count - 1) +
                                                                        botnet_flows_count[host]) / window_count

                        # Tell GUI to update the time series plot
                        self.data_signal.emit(self.data)

                        # Do clustering on suspected botnet flows
                        botnet_hosts = {}

                        for flow, x in botnet_flows:
                            x = list(x)
                            src, dst = fp.get_src_dst(flow)

                            if src.startswith(self.internal_hosts_prefix):
                                if src not in botnet_hosts:
                                    botnet_hosts[src] = {}
                                    botnet_hosts[src]['count'] = 1
                                    botnet_hosts[src]['srcpkts'] = x[2]
                                    botnet_hosts[src]['dstpkts'] = x[3]
                                    botnet_hosts[src]['srcbytes'] = x[4]
                                    botnet_hosts[src]['dstbytes'] = x[5]
                                    botnet_hosts[src]['unique_ports'] = {flow[3]}
                                    botnet_hosts[src]['unique_dsts'] = {dst}
                                else:
                                    botnet_hosts[src]['count'] += 1
                                    botnet_hosts[src]['srcpkts'] += x[2]
                                    botnet_hosts[src]['dstpkts'] += x[3]
                                    botnet_hosts[src]['srcbytes'] += x[4]
                                    botnet_hosts[src]['dstbytes'] += x[5]
                                    botnet_hosts[src]['unique_ports'].add(flow[3])
                                    botnet_hosts[src]['unique_dsts'].add(dst)

                            if dst.startswith(self.internal_hosts_prefix):
                                if dst not in botnet_hosts:
                                    botnet_hosts[dst] = {}
                                    botnet_hosts[dst]['count'] = 1
                                    botnet_hosts[dst]['srcpkts'] = x[3]
                                    botnet_hosts[dst]['dstpkts'] = x[2]
                                    botnet_hosts[dst]['srcbytes'] = x[5]
                                    botnet_hosts[dst]['dstbytes'] = x[4]
                                    botnet_hosts[dst]['unique_ports'] = {flow[1]}
                                    botnet_hosts[dst]['unique_dsts'] = {src}
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
                            new_xs.append(
                                [curr['count'], curr['srcpkts'], curr['dstpkts'], curr['srcbytes'], curr['dstbytes'],
                                 len(curr['unique_ports']) / 65535, len(curr['unique_dsts'])])

                        scaled_xs = StandardScaler().fit_transform(new_xs)
                        ac = AgglomerativeClustering().fit(scaled_xs)

                        labels = ac.labels_

                        clusters = {}

                        for host, label in zip(ips, labels):
                            if label not in clusters:
                                clusters[label] = {host}
                            else:
                                clusters[label].add(host)

                        # define 0 as the majority/normal cluster and 1 as the anomalous cluster
                        if len(clusters[1]) > len(clusters[0]):
                            clusters = {0:clusters[1], 1:clusters[0]}

                        # Update the ranking with the new info
                        ALPHA = 0.3

                        for host in clusters[0]:
                            if host not in self.hosts_ranking:
                                self.hosts_ranking[host] = {'score': 0.0, 'consec': 0, 'color': 'white'}

                            curr = self.hosts_ranking[host]
                            r_prev = curr['score']
                            r_now = 0.0
                            curr['score'] = ALPHA * r_now + (1 - ALPHA) * r_prev

                            if curr['score'] >= 0.85 or (curr['score'] >= 0.60 and curr['score'] > r_prev):
                                curr['consec'] += 1
                                if curr['consec'] >= 3:
                                    curr['color'] = 'red'
                            else:
                                curr['consec'] = 0
                                if curr['color'] in {'red', 'yellow'} and curr['score'] >= 0.1:
                                    curr['color'] = 'yellow'
                                else:
                                    curr['color'] = 'white'

                        for host in clusters[1]:
                            if host not in self.hosts_ranking:
                                self.hosts_ranking[host] = {'score': 0.0, 'consec': 0, 'color': 'white'}

                            curr = self.hosts_ranking[host]
                            r_prev = curr['score']
                            r_now = 1.0
                            curr['score'] = ALPHA * r_now + (1 - ALPHA) * r_prev

                            if curr['score'] >= 0.85 or (curr['score'] >= 0.60 and curr['score'] > r_prev):
                                curr['consec'] += 1
                                if curr['consec'] >= 3:
                                    curr['color'] = 'red'
                            else:
                                curr['consec'] = 0
                                if curr['color'] in {'red', 'yellow'} and curr['score'] >= 0.1:
                                    curr['color'] = 'yellow'
                                else:
                                    curr['color'] = 'white'

                        # Tell GUI to update the ranking
                        self.hosts_updated_signal.emit(self.hosts_ranking)
                        self.window_id += 1
                    else:
                        # append 0 before it ends TODO
                        # break
                        self.statusinfo_signal.emit("[PERM]Waiting on: " + current_fname + "...")
                        time.sleep(5)

            os.chdir(self.owd)

    '''
    Stop thread
    '''

    def stop(self):
        # Must protect self._stop with a mutex because the secondary thread
        # might try to access it at the same time.
        with self.stop_mutex:
            self._stop = True


'''
Main window displaying the graphs.
'''


class MainApplication(QtGui.QWidget):
    pcap_file = ''
    pcap_folder = ''
    window_length = ''
    overlap_length = ''
    internal_hosts_prefix = ''

    thread1 = ''
    thread2 = ''
    data = ''

    def __init__(self, pcap_file, pcap_folder, window_length, overlap_length, internal_hosts_prefix):
        super(MainApplication, self).__init__()
        self.initUI()

        self.pcap_file = pcap_file
        self.pcap_folder = pcap_folder
        self.window_length = window_length
        self.overlap_length = overlap_length
        self.internal_hosts_prefix = internal_hosts_prefix

        # Initialise multithreading, worker thread for background processing
        self.thread2 = WorkerThread(MODELS_FOLDER, FEATURES_LIST, window_length, overlap_length, internal_hosts_prefix)
        self.thread2.statusinfo_signal.connect(self.update_statusbar)
        self.thread2.set_mode(OFFLINE_FOLDER, pcap_folder=pcap_folder)

        # When models are loaded signal main UI to update dropdown
        self.thread2.models_loaded_signal.connect(self.update_models_dropdown)

        # Whenever new hosts are found signal main UI to update dropdown
        self.thread2.hosts_updated_signal.connect(self.update_table)

        # Whenever new graph points are received signal main UI to update graph
        self.thread2.data_signal.connect(self.update)

        # Begin the worker thread
        self.thread2.start()

    def initUI(self):
        self.setGeometry(10, 10, 1000, 900)
        self.setWindowTitle('Botnet detector')
        self.setWindowIcon(QtGui.QIcon('../etc/favicon.png'))

        # Statusbar
        self.statusbar = QtGui.QStatusBar()
        self.statusbar.setSizeGripEnabled(False)
        self.statusbar.showMessage("Initializing...")
        self.permstatuslabel = QtGui.QLabel("Initializing...")
        self.statusbar.addPermanentWidget(self.permstatuslabel)

        # Text labels
        l1 = QtGui.QLabel("Model")
        l2 = QtGui.QLabel("Network hosts")

        # Dropdown menus
        self.models_dropdown = QtGui.QComboBox(self)
        self.models_dropdown.setMinimumContentsLength(15)
        self.models_dropdown.setSizeAdjustPolicy(QtGui.QComboBox.AdjustToContents)
        self.models_dropdown.activated[str].connect(self.change_models)

        self.hosts_dropdown = QtGui.QComboBox(self)
        self.hosts_dropdown.setMinimumContentsLength(15)
        self.hosts_dropdown.setSizeAdjustPolicy(QtGui.QComboBox.AdjustToContents)
        self.hosts_dropdown.activated[str].connect(self.change_hosts)

        # Plot widget
        self.plotwidget = pg.PlotWidget()
        self.plotwidget.setLimits(xMin=0, yMin=0)

        # Table
        self.table = QtGui.QTableWidget()
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(QtCore.QString("host;score;").split(";"))
        self.table.horizontalHeader().setResizeMode(0, QtGui.QHeaderView.Stretch)
        self.table.setEditTriggers(QtGui.QAbstractItemView.NoEditTriggers)
        self.table.setDragDropOverwriteMode(False)
        self.table.setDragDropMode(QtGui.QAbstractItemView.NoDragDrop)
        self.table.setSelectionMode(QtGui.QAbstractItemView.ExtendedSelection)
        self.table.setSelectionBehavior(QtGui.QAbstractItemView.SelectRows)

        # Set layout
        self.hbox = QtGui.QHBoxLayout()
        self.vbox = QtGui.QVBoxLayout()

        self.vbox.addWidget(l1)
        self.vbox.addWidget(self.models_dropdown)
        self.vbox.addStretch(1)
        self.vbox.addWidget(l2)
        self.vbox.addWidget(self.hosts_dropdown)
        self.vbox.addStretch(2)

        self.hbox.addWidget(self.plotwidget)
        self.hbox.addLayout(self.vbox)

        self.vbox2 = QtGui.QVBoxLayout()
        self.vbox2.addLayout(self.hbox, 3)
        self.vbox2.addWidget(self.table, 2)

        self.vbox2.addStretch()
        self.vbox2.addWidget(self.statusbar)

        self.setLayout(self.vbox2)

        self.center()
        self.show()

    def closeEvent(self, event):
        reply = QtGui.QMessageBox.question(self, 'Message',
                                           "Are you sure to quit?", QtGui.QMessageBox.Yes |
                                           QtGui.QMessageBox.No, QtGui.QMessageBox.No)

        if reply == QtGui.QMessageBox.Yes:
            if self.thread1 != '':
                self.thread1.quit()
            self.thread2.quit()
            event.accept()
        else:
            event.ignore()

    def center(self):
        qr = self.frameGeometry()
        cp = QtGui.QDesktopWidget().availableGeometry().center()
        qr.moveCenter(cp)
        self.move(qr.topLeft())

    def update_statusbar(self, message):
        if str(message).startswith("[PERM]"):
            self.permstatuslabel.setText(message[6:])
        else:
            self.statusbar.showMessage(message)

    def update_table(self, hosts_ranking):
        row_count = self.table.rowCount()
        row_diff = len(hosts_ranking) - row_count
        if row_diff > 0:
            for i in range(row_count, row_count + row_diff):
                self.table.insertRow(i)

        row = 0
        for host, ranking_info in sorted(hosts_ranking.items(), key=lambda x: x[1]['score'], reverse=True):
            if host == 'ALL':
                continue

            score = ranking_info['score']
            color = ranking_info['color']

            self.table.setItem(row, 0, QtGui.QTableWidgetItem(host))
            self.table.setItem(row, 1, QtGui.QTableWidgetItem("{:.4f}".format(score)))

            if color == 'red':
                self.table.item(row, 0).setBackground(QtGui.QColor(255, 150, 150))
                self.table.item(row, 1).setBackground(QtGui.QColor(255, 150, 150))
            elif color == 'yellow':
                self.table.item(row, 0).setBackground(QtGui.QColor(255, 228, 136))
                self.table.item(row, 1).setBackground(QtGui.QColor(255, 228, 136))

            row += 1

    def update_hosts_dropdown(self):
        selected_model = int(str(self.models_dropdown.currentText().split(":")[0]))
        self.hosts_dropdown.clear()
        for host in sorted(self.data[selected_model].keys()):
            self.hosts_dropdown.addItem(host)

    def update_models_dropdown(self, models):
        # Initialise background thread for making NetFlow files if the folder does not already exist
        if not os.path.isdir(self.pcap_folder):
            self.thread1 = NetflowThread(self.pcap_file, self.window_length, self.overlap_length)
            self.thread1.statusinfo_signal.connect(self.update_statusbar)
            self.thread1.start()
        else:
            self.statusbar.showMessage(self.pcap_folder + " already exists. Skipping Netflow generation...")
            self.permstatuslabel.setText("Using existing folder")

        # Add models to dropdown
        for model_name in models:
            self.models_dropdown.addItem(model_name)

    def change_hosts(self, text):
        selected_model = int(str(self.models_dropdown.currentText().split(":")[0]))
        selected_host = str(text)
        curve = self.data[selected_model][selected_host]['series']
        self.plotwidget.plot(curve, clear=True)

    def change_models(self, text):
        selected_model = int(str(text.split(":")[0]))
        print("selected model is: " + str(selected_model))
        self.update_hosts_dropdown()

        # selected_host = str(self.hosts_dropdown.currentText())
        # if selected_host != '':
        #     curve = self.data[selected_model][selected_host]
        #     self.plotwidget.plot(curve, clear=True)

    def update(self, data):
        self.data = data
        selected_model = int(str(self.models_dropdown.currentText().split(":")[0]))
        prev_selected_host = str(self.hosts_dropdown.currentText())
        self.update_hosts_dropdown()

        if prev_selected_host != '':
            index = self.hosts_dropdown.findText(prev_selected_host, QtCore.Qt.MatchFixedString)
            if index >= 0:
                self.hosts_dropdown.setCurrentIndex(index)
                selected_host = prev_selected_host
            else:
                selected_host = str(self.hosts_dropdown.currentText())
        else:
            selected_host = str(self.hosts_dropdown.currentText())

        curve = self.data[selected_model][selected_host]['series']

        self.plotwidget.plot(curve, clear=True)
        # self.plotwidget.setXRange(x1, x2)


'''
Main function
'''


def main():
    wc = WindowContainer()
    app = QtGui.QApplication(sys.argv)
    launcher = Launcher(wc)
    # main_app = MainApplication("/media/SURF2017/SURF2017/datasets/CTU-13-Dataset/9/capture20110817pcaptruncated_300_150")
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
