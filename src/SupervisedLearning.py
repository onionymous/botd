# SURF2017
# File: SupervisedLearning.py
# Created: 7/5/17
# Author: Stephanie Ding

from collections import Counter
import constants
import pydotplus
import FlowParser as fp
import numpy as np
from sklearn import tree
from sklearn.naive_bayes import GaussianNB
from sklearn import svm
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.externals import joblib
from sklearn.metrics import confusion_matrix, accuracy_score

TEST_PARTITION_SIZE = 50000

TRAINING_FILE_ALL = "../datasets/13/capture20110815-3.truncated_flows.txt"
TRAINING_FILE_NORMAL = "../datasets/9/ds9_300_normal.csv"
TRAINING_FILE_BOTNET = "../datasets/13/botnet-capture-20110815-fast-flux-2_flows.txt"

DT_MODEL_FILENAME = "../models/ds9_dt.pkl"
RF_MODEL_FILENAME = "../models/ds9_rf.pkl"
NB_MODEL_FILENAME = "../models/ds9_nb.pkl"
SVM_MODEL_FILENAME = "../models/ds9_svm.pkl"

PNG_FILENAME = "../datasets/9/dtree.pdf"

FILE_TO_PREDICT = "../datasets/9/T_all_flows/flows/dataset9_00046_20110817065101_flows.txt"

def custom_loss(ground_truth, predictions):
    # TODO
    pass

def train_DT(train_x, train_y, test_flows, test_x, test_y, infected_hosts_ips):
    # Train
    clf = tree.DecisionTreeClassifier()
    clf = clf.fit(train_x, train_y)

    # evaluate model with testing dataset
    print("Testing accuracy on unseen test dataset of size: " + str(len(test_x)))
    #acc = clf.score(test_x, test_y)
    predicted = clf.predict(test_x)
    acc = accuracy_score(predicted, test_y)

    print("acc: " + str(acc))

    cm = confusion_matrix(test_y, predicted)

    TN = cm[0][0]
    FN = cm[0][1]
    FP = cm[1][0]
    TP = cm[1][1]

    print("True positive: " + str(TP))
    print("False positive: " + str(FP))
    print("False negative: " + str(FN))
    print("True negative: " + str(TN))

    get_hosts_statistics(test_flows, predicted, infected_hosts_ips)

    joblib.dump(clf, DT_MODEL_FILENAME)
    # clf = joblib.load('filename.pkl')

    # save png of decision tree
    # dot_data = tree.export_graphviz(clf, feature_names=tp.headers(), out_file=None)
    # graph = pydotplus.graph_from_dot_data(dot_data)
    # graph.write_pdf(PNG_FILENAME)

def train_RF(train_x, train_y, test_flows, test_x, test_y, infected_hosts_ips):
    # Train
    clf = RandomForestClassifier(n_estimators=100)
    clf = clf.fit(train_x, train_y)

    # evaluate model with testing dataset
    print("Testing accuracy on unseen test dataset of size: " + str(len(test_x)))
    #acc = clf.score(test_x, test_y)
    predicted = clf.predict(test_x)
    acc = accuracy_score(predicted, test_y)

    print("acc: " + str(acc))

    cm = confusion_matrix(test_y, predicted)

    TN = cm[0][0]
    FP = cm[0][1]
    FN = cm[1][0]
    TP = cm[1][1]

    print("True positive: " + str(TP))
    print("False positive: " + str(FP))
    print("False negative: " + str(FN))
    print("True negative: " + str(TN))

    get_hosts_statistics2(test_flows, predicted, infected_hosts_ips)
    #get_hosts_statistics2(test_flows, predicted, infected_hosts_ips)

    joblib.dump(clf, RF_MODEL_FILENAME)

def train_NB(train_x, train_y, test_flows, test_x, test_y, infected_hosts_ips):
    # Train
    clf = GaussianNB()
    clf = clf.fit(train_x, train_y)

    # evaluate model with testing dataset
    print("Testing accuracy on unseen test dataset of size: " + str(len(test_x)))
    #acc = clf.score(test_x, test_y)
    predicted = clf.predict(test_x)
    acc = accuracy_score(predicted, test_y)

    print("acc: " + str(acc))

    cm = confusion_matrix(test_y, predicted)

    TN = cm[0][0]
    FN = cm[0][1]
    FP = cm[1][0]
    TP = cm[1][1]

    print("True positive: " + str(TP))
    print("False positive: " + str(FP))
    print("False negative: " + str(FN))
    print("True negative: " + str(TN))

    get_hosts_statistics(test_flows, predicted, infected_hosts_ips)

    joblib.dump(clf, NB_MODEL_FILENAME)


def train_SVM(train_x, train_y, test_flows, test_x, test_y, infected_hosts_ips):
    # Train
    clf = svm.SVC()
    clf = clf.fit(train_x, train_y)

    # evaluate model with testing dataset
    print("Testing accuracy on unseen test dataset of size: " + str(len(test_x)))
    #acc = clf.score(test_x, test_y)
    predicted = clf.predict(test_x)
    acc = accuracy_score(predicted, test_y)

    print("acc: " + str(acc))

    cm = confusion_matrix(test_y, predicted)

    TP = cm[1][1]
    FP = cm[0][1]
    FN = cm[1][0]
    TN = cm[0][0]

    print("True positive: " + str(TP))
    print("False positive: " + str(FP))
    print("False negative: " + str(FN))
    print("True negative: " + str(TN))

    get_hosts_statistics(test_flows, predicted, infected_hosts_ips)

    joblib.dump(clf, SVM_MODEL_FILENAME)

def get_hosts_statistics(flows, y_pred, infected_hosts_ips):
    network_prefix = ".".join(next(iter(infected_hosts_ips)).split(".")[:2])

    all_src_IPs = set()
    LAN_IPs = set()

    botnet_dsts = {}
    correct_botnets = set()
    incorrect_botnets = set()
    correct_normal = set()
    incorrect_normal = set()

    for i, y in enumerate(y_pred):
        src, dst = fp.get_src_dst(flows[i])
        all_src_IPs.add(src)
        if src.startswith(network_prefix):
            LAN_IPs.add(src)

        if y == 0:
            if src not in infected_hosts_ips and src.startswith(network_prefix):
                correct_normal.add(src)
            else:
                if src.startswith(network_prefix):
                    incorrect_normal.add(src)
        else:
            if dst in botnet_dsts: # and not dst.startswith(network_prefix):
                botnet_dsts[dst] += 1
            else:
                botnet_dsts[dst] = 1

            if src in infected_hosts_ips:
                correct_botnets.add(src)
            else:
                if src.startswith(network_prefix):
                    incorrect_botnets.add(src)

    most_common = dict(Counter(botnet_dsts).most_common(5))
    c2 = max(botnet_dsts, key=lambda x: botnet_dsts[x])
    print("Most common: " + str(most_common))

    botnet_dst_comms = set()
    errors = 0
    for i, y in enumerate(y_pred):
        src, dst = fp.get_src_dst(flows[i])
        if y == 1 and dst == c2 and src.startswith(network_prefix):
            botnet_dst_comms.add(src)
            if src not in infected_hosts_ips:
                errors += 1

    print("Total " + str(len(all_src_IPs)) + " unique source IPs")
    print("Total " + str(len(LAN_IPs)) + " LAN source IPs")
    print("Total of " + str(len(correct_botnets)) + " correctly classified botnet IPs")
    print("Total of " + str(len(incorrect_botnets)) + " incorrectly classified botnet IPs")
    # print("Total of " + str(len(LAN_IPs) - len(correct_botnets.union(incorrect_botnets))) + " correctly classified normal IPs")
    # print("Total of " + str(len(LAN_IPs) - len(correct_botnets)) + " incorrectly classified normal IPs")
    print("Total of " + str(len(botnet_dsts)) + " identified as remote botnet IPs")
    print("Total of " + str(len(botnet_dst_comms)) + " hosts communicating with probable C&C")
    print(sorted(list(botnet_dst_comms)))

def get_hosts_statistics2(flows, y_pred, infected_hosts_ips):
    network_prefix = ".".join(next(iter(infected_hosts_ips)).split(".")[:2])

    all_src_IPs = set()
    LAN_IPs = set()

    correct_botnets = set()
    incorrect_botnets = set()
    correct_normal = set()
    incorrect_normal = set()

    botnet_srcs = {}
    botnet_dsts = {}

    for i, y in enumerate(y_pred):
        src, dst = fp.get_src_dst(flows[i])
        all_src_IPs.add(src)
        if src.startswith(network_prefix):
            LAN_IPs.add(src)

        if y == 1:
            if src.startswith(network_prefix):
                if src not in botnet_srcs:
                    botnet_srcs[src] = 1
                else:
                    botnet_srcs[src] += 1

            if dst in botnet_dsts: # and not dst.startswith(network_prefix):
                botnet_dsts[dst] += 1
            else:
                botnet_dsts[dst] = 1

        if y == 0:
            if src not in infected_hosts_ips and src.startswith(network_prefix):
                correct_normal.add(src)
            else:
                if src.startswith(network_prefix):
                    incorrect_normal.add(src)


    most_common_srcs = dict(Counter(botnet_srcs).most_common(15))
    # c2 = max(botnet_dsts, key=lambda x: botnet_dsts[x])
    print("Most common srcs: " + str(most_common_srcs))

    most_common_dsts = dict(Counter(botnet_dsts).most_common(5))
    #c2 = max(botnet_dsts, key=lambda x: botnet_dsts[x])
    print("Most common dsts: " + str(most_common_dsts))



def get_feature_importances(filename):
    clf = joblib.load(filename)
    print("Feature importances in descending order:")
    for feature, imp in sorted(zip(fp.ARGUS_FIELDS, clf.feature_importances_), key=lambda x: x[1], reverse=True):
        print(feature + " " + str(imp * 100) + "%")


def train_tranalyzer():
    dataset_no = int(input("Enter the number for the dataset: "))
    assert(dataset_no >= 1 and dataset_no <= 13) # for security
    infected_hosts_ips = eval("constants.DATASET_" + str(dataset_no) + "_INFECTED_HOSTS")

    global DT_MODEL_FILENAME
    global RF_MODEL_FILENAME
    global NB_MODEL_FILENAME
    global SVM_MODEL_FILENAME

    DT_MODEL_FILENAME = "../models/ds" + str(dataset_no) + "_dt.pkl"
    RF_MODEL_FILENAME = "../models/ds" + str(dataset_no) + "_rf.pkl"
    NB_MODEL_FILENAME = "../models/ds" + str(dataset_no) + "_nb.pkl"
    SVM_MODEL_FILENAME = "../models/ds" + str(dataset_no) + "_svm.pkl"

    labelled = raw_input("Enter the filename for the labelled Argus file: ")
    flows_file = raw_input("Enter the filename for the Tranalyzer flows: ")
    flows, xs, ys = fp.parse_tranalyzer(labelled, flows_file)

    test_partition_size = int(0.3 * len(xs)) # use 0.3 of the entire dataset as testing, the rest for training

    test_flows = flows[:test_partition_size]
    test_x = np.array(xs[:test_partition_size])
    test_y = np.array([y[0] for y in ys][:test_partition_size])

    train_flows = flows[test_partition_size:]
    train_x = np.array(xs[test_partition_size:])
    train_y = np.array([y[0] for y in ys][test_partition_size:])

    print("Number of training flows (70% of dataset): " + str(len(train_x)))
    print("Number of testing flows (30% of dataset): " + str(len(test_x)))

    print('')
    print("Training decision tree:")
    train_DT(train_x, train_y, test_flows, test_x, test_y, infected_hosts_ips)

    print('')
    print("Training random forest:")
    train_RF(train_x, train_y, test_flows, test_x, test_y, infected_hosts_ips)

    print('')
    print("Training Naive Bayes:")
    train_NB(train_x, train_y, test_flows, test_x, test_y, infected_hosts_ips)

    #print('')
    #print("Training SVM:")
    #train_SVM(train_x, train_y, test_flows, test_x, test_y, infected_hosts_ips)
    #print('')

def train_argus():
    dataset_no = int(input("Enter the number for the dataset: "))
    assert (dataset_no >= 1 and dataset_no <= 13)  # for security
    infected_hosts_ips = eval("constants.DATASET_" + str(dataset_no) + "_INFECTED_HOSTS")

    global DT_MODEL_FILENAME
    global RF_MODEL_FILENAME
    global NB_MODEL_FILENAME
    global SVM_MODEL_FILENAME

    DT_MODEL_FILENAME = "../models/ds" + str(dataset_no) + "_A_dt.pkl"
    RF_MODEL_FILENAME = "../models/ds" + str(dataset_no) + "_A_rf.pkl"
    NB_MODEL_FILENAME = "../models/ds" + str(dataset_no) + "_A_nb.pkl"
    SVM_MODEL_FILENAME = "../models/ds" + str(dataset_no) + "_A_svm.pkl"

    labelled = raw_input("Enter the filename for the labelled Argus binetflows: ")
    unlabelled = raw_input("Enter the filename for the extended Argus binetflows: ")
    features_list = raw_input("Enter space-separated list of features (or press enter to use default set of 40): ")

    try:
        if features_list != '':
            features_list = features_list.split()
        else:
            features_list = fp.ARGUS_FIELDS
    except Exception, e:
        features_list = fp.ARGUS_FIELDS

    print("Using features list: " + str(features_list))

    train_flows, train_x, train_y, test_flows, test_x, test_y = fp.parse_argus(labelled, unlabelled, features_list)

    # test_partition_size = int(0.3 * len(xs))  # use 0.3 of the entire dataset as testing, the rest for training

    # test_flows = flows[:test_partition_size]
    # test_x = np.array(xs[:test_partition_size])
    # test_y = np.array([y[0] for y in ys][:test_partition_size])
    #
    # train_flows = flows[test_partition_size:]
    # train_x = np.array(xs[test_partition_size:])
    # train_y = np.array([y[0] for y in ys][test_partition_size:])


    #print('')
    #print("Training decision tree:")
    #train_DT(train_x, train_y, test_flows, test_x, test_y, infected_hosts_ips)

    print('')
    print("Training random forest:")
    train_RF(train_x, train_y, test_flows, test_x, test_y, infected_hosts_ips)

    #print('')
    #print("Training Naive Bayes:")
    #train_NB(train_x, train_y, test_flows, test_x, test_y, infected_hosts_ips)

def train_iscx():
    global DT_MODEL_FILENAME
    global RF_MODEL_FILENAME
    global NB_MODEL_FILENAME
    global SVM_MODEL_FILENAME

    DT_MODEL_FILENAME = "../models/ISCX_dt_40.pkl"
    RF_MODEL_FILENAME = "../models/ISCX_rf_40.pkl"
    NB_MODEL_FILENAME = "../models/ISCX_nb_40.pkl"
    SVM_MODEL_FILENAME = "../models/ISCX_svm_40.pkl"

    TRAIN_FILE = "/media/SURF2017/ISCX_2014_Botnet_Dataset/ISCX_Botnet-Training.binetflow"
    TEST_FILE = "/media/SURF2017/ISCX_2014_Botnet_Dataset/ISCX_Botnet-Testing.binetflow"
    features_list = raw_input("Enter space-separated list of features (or press enter to use default set of 40): ")

    try:
        if features_list != '':
            features_list = features_list.split()
        else:
            features_list = fp.ARGUS_FIELDS
    except Exception, e:
        features_list = fp.ARGUS_FIELDS

    print("Using features list: " + str(features_list))

    flows, train_x, train_y = fp.parse_iscx(TRAIN_FILE, features_list)
    test_flows, test_x, test_y = fp.parse_iscx(TEST_FILE, features_list)

    print("\nTraining decision tree:")
    clf = tree.DecisionTreeClassifier()
    clf = clf.fit(train_x, train_y)
    joblib.dump(clf, DT_MODEL_FILENAME)

    print("Testing accuracy on unseen test dataset of size: " + str(len(test_x)))
    # acc = clf.score(test_x, test_y)
    predicted = clf.predict(test_x)
    acc = accuracy_score(predicted, test_y)

    print("acc: " + str(acc))


    print("\nTraining random forest:")
    clf = RandomForestClassifier(n_estimators=100)
    clf = clf.fit(train_x, train_y)
    joblib.dump(clf, RF_MODEL_FILENAME)

    print("Testing accuracy on unseen test dataset of size: " + str(len(test_x)))
    # acc = clf.score(test_x, test_y)
    predicted = clf.predict(test_x)
    acc = accuracy_score(predicted, test_y)

    print("acc: " + str(acc))


    print("\nTraining Naive Bayes:")
    clf = GaussianNB()
    clf = clf.fit(train_x, train_y)
    joblib.dump(clf, NB_MODEL_FILENAME)

    print("Testing accuracy on unseen test dataset of size: " + str(len(test_x)))
    # acc = clf.score(test_x, test_y)
    predicted = clf.predict(test_x)
    acc = accuracy_score(predicted, test_y)

    print("acc: " + str(acc))


    print("\nTraining SVM:")
    clf = svm.SVC()
    clf = clf.fit(train_x, train_y)
    joblib.dump(clf, SVM_MODEL_FILENAME)

    print("Testing accuracy on unseen test dataset of size: " + str(len(test_x)))
    # acc = clf.score(test_x, test_y)
    predicted = clf.predict(test_x)
    acc = accuracy_score(predicted, test_y)

    print("acc: " + str(acc))


def test_model(model_filename, flows, test_x, test_y):
    clf = joblib.load(model_filename)
    print("Testing accuracy on unseen test dataset of size: " + str(len(test_x)))
    predicted = clf.predict(test_x)
    acc = accuracy_score(predicted, test_y)

    TP = 0
    TN = 0
    FP = 0
    FN = 0

    for y_actual, y_pred in zip(test_y, predicted):
        if y_actual == 0 and y_pred == 0:
            TN += 1
        elif y_actual == 0 and y_pred == 1:
            FP += 1
        elif y_actual == 1 and y_pred == 0:
            FN += 1
        elif y_actual == 1 and y_pred == 1:
            TP += 1

    print("acc: " + str(acc))
    print("True positive: " + str(TP))
    print("False positive: " + str(FP))
    print("False negative: " + str(FN))
    print("True negative: " + str(TN))


def main():
    np.random.seed(0)

    features_list = raw_input("Enter space-separated list of features (or press enter to use default set of 40): ")

    try:
        if features_list != '':
            features_list = features_list.split()
        else:
            features_list = fp.ARGUS_FIELDS
    except Exception, e:
        features_list = fp.ARGUS_FIELDS

    print("Using features list: " + str(features_list))

    labelled = raw_input("Enter the filename for the labelled Argus file: ")
    # flows_file = raw_input("Enter the filename for the extended flows: ")

    # flows, test_x, test_y = fp.parse_ctu(flows_file, labelled, features_list, sample_rate=0)

    sess = fp.ArgusBatchSession(labelled, features_list, 300, 150)
    # clf = RandomForestClassifier(n_estimators=100)
    clf = GradientBoostingClassifier(n_estimators=100)

    # sess.train_model_on_file(clf, 100000, 10000, "../models/ctu9_40_full.pkl", flows_file)
    sess.train_model_on_folder(clf, 100000, 10000, "../models/ctu9_40_300_gb.pkl", "/media/SURF2017/CTU-13-Dataset/9/capture20110817pcaptruncated_300_150", 56, 125)

    # clf = joblib.load("/media/SURF2017/SURF2017/models/ctu9_40_full.pkl")
    sess.test_model_on_folder(clf, "/media/SURF2017/CTU-13-Dataset/9/capture20110817pcaptruncated_300_150", 56)

    # test_model("../models/ISCX_rf_40.pkl", flows, test_x, test_y)
    #train_iscx()
    # print("Dataset 5: ")
    # get_feature_importances('/media/SURF2017/SURF2017/models/ctu5_40_300.pkl')
    #
    # print("Dataset 6: ")
    # get_feature_importances('/media/SURF2017/SURF2017/models/ctu6_40_300.pkl')
    #
    # print("Dataset 7: ")
    # get_feature_importances('/media/SURF2017/SURF2017/models/ctu7_40_300.pkl')
    #
    # print("Dataset 9: ")
    # get_feature_importances('/media/SURF2017/SURF2017/models/ctu9_40_300.pkl')
    #
    # print("\nDataset 10: ")
    # get_feature_importances('/media/SURF2017/SURF2017/models/ctu10_40_300.pkl')
    #
    # print("\nDataset 11:")
    # get_feature_importances('/media/SURF2017/SURF2017/models/ctu11_40_300.pkl')
    #
    # print("\nDataset 12:")
    # get_feature_importances('/media/SURF2017/SURF2017/models/ctu12_40_300.pkl')
    #
    # print("\nDataset 13:")
    # get_feature_importances('/media/SURF2017/SURF2017/models/ctu13_40_300.pkl')


if __name__ == "__main__":
    main()
