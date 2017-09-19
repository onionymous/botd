# SURF2017
# File: SupervisedLearning_DS9.py
# Created: 7/5/17
# Author: Stephanie Ding

import constants
import pydotplus
import FlowParser as tp
import numpy as np
from collections import Counter
from sklearn import tree
from sklearn.naive_bayes import GaussianNB
from sklearn import svm
from sklearn.ensemble import RandomForestClassifier
from sklearn.externals import joblib
from sklearn.metrics import confusion_matrix, accuracy_score

TEST_PARTITION_SIZE = 50000

TRAINING_FILE_ALL = "../datasets/9/capture20110817.truncated_flows.txt"
TRAINING_FILE_NORMAL = "../datasets/9/ds9_300_normal.csv"
TRAINING_FILE_BOTNET = "../datasets/9/botnet-capture-20110817-bot_flows.txt"

DT_MODEL_FILENAME = "../models/ds9_dt.pkl"
RF_MODEL_FILENAME = "../models/ds9_rf.pkl"
NB_MODEL_FILENAME = "../models/ds9_nb.pkl"
SVM_MODEL_FILENAME = "../models/ds9_svm.pkl"

PNG_FILENAME = "../datasets/9/dtree.pdf"

FILE_TO_PREDICT = "../datasets/9/T_all_flows/flows/dataset9_00046_20110817065101_flows.txt"

def custom_loss(ground_truth, predictions):
    loss = 0
    pass

def train_DT(train_x, train_y, test_flows, test_x, test_y):
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

    TP = cm[0][0]
    FP = cm[0][1]
    FN = cm[1][0]
    TN = cm[1][1]

    print("True positive: " + str(TP))
    print("False positive: " + str(FP))
    print("False negative: " + str(FN))
    print("True negative: " + str(TN))

    get_hosts_statistics(test_flows, predicted)

    joblib.dump(clf, DT_MODEL_FILENAME)
    # clf = joblib.load('filename.pkl')

    # save png of decision tree
    # dot_data = tree.export_graphviz(clf, feature_names=tp.headers(), out_file=None)
    # graph = pydotplus.graph_from_dot_data(dot_data)
    # graph.write_pdf(PNG_FILENAME)

def train_RF(train_x, train_y, test_flows, test_x, test_y):
    # Train
    clf = RandomForestClassifier()
    clf = clf.fit(train_x, train_y)

    # evaluate model with testing dataset
    print("Testing accuracy on unseen test dataset of size: " + str(len(test_x)))
    #acc = clf.score(test_x, test_y)
    predicted = clf.predict(test_x)
    acc = accuracy_score(predicted, test_y)

    print("acc: " + str(acc))

    cm = confusion_matrix(test_y, predicted)

    TP = cm[0][0]
    FP = cm[0][1]
    FN = cm[1][0]
    TN = cm[1][1]

    print("True positive: " + str(TP))
    print("False positive: " + str(FP))
    print("False negative: " + str(FN))
    print("True negative: " + str(TN))

    get_hosts_statistics(test_flows, predicted)

    joblib.dump(clf, RF_MODEL_FILENAME)

def train_NB(train_x, train_y, test_flows, test_x, test_y):
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

    TP = cm[0][0]
    FP = cm[0][1]
    FN = cm[1][0]
    TN = cm[1][1]

    print("True positive: " + str(TP))
    print("False positive: " + str(FP))
    print("False negative: " + str(FN))
    print("True negative: " + str(TN))

    get_hosts_statistics(test_flows, predicted)

    joblib.dump(clf, NB_MODEL_FILENAME)


def train_SVM(train_x, train_y, test_flows, test_x, test_y):
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

    TP = cm[0][0]
    FP = cm[0][1]
    FN = cm[1][0]
    TN = cm[1][1]

    print("True positive: " + str(TP))
    print("False positive: " + str(FP))
    print("False negative: " + str(FN))
    print("True negative: " + str(TN))

    get_hosts_statistics(test_flows, predicted)

    joblib.dump(clf, SVM_MODEL_FILENAME)

def get_hosts_statistics(flows, y_pred):
    botnet_dsts = {}
    correct_botnets = set()
    incorrect_botnets = set()
    correct_normal = set()
    incorrect_normal = set()

    for i, y in enumerate(y_pred):
        src, dst = tp.get_src_dst(flows[i])
        if y == 0:
            if src not in constants.DATASET_9_INFECTED_HOSTS:
                correct_normal.add(src)
            else:
                incorrect_normal.add(src)
        else:
            if dst in botnet_dsts:
                botnet_dsts[dst] += 1
            else:
                botnet_dsts[dst] = 1

            if flows[i][2] in constants.DATASET_9_INFECTED_HOSTS:
                correct_botnets.add(src)
            else:
                incorrect_botnets.add(src)

    most_common = dict(Counter(botnet_dsts).most_common(5))
    c2 = max(botnet_dsts, key=lambda x: botnet_dsts[x])
    print("Most common: " + str(most_common))

    botnet_dst_comms = set()
    errors = 0
    for i, y in enumerate(y_pred):
        src, dst = tp.get_src_dst(flows[i])
        if dst == c2:
            botnet_dst_comms.add(src)
            if src not in constants.DATASET_9_INFECTED_HOSTS:
                errors += 1

    print("Total " + str(len(correct_botnets.union(incorrect_botnets, correct_normal, incorrect_normal))) + " unique host IPs on network")
    print("Total of " + str(len(correct_botnets)) + " correctly classified botnet IPs")
    print("Total of " + str(len(incorrect_botnets)) + " incorrectly classified botnet IPs")
    print("Total of " + str(len(correct_normal)) + " correctly classified normal IPs")
    print("Total of " + str(len(incorrect_normal)) + " incorrectly classified normal IPs")
    print("Total of " + str(len(botnet_dsts)) + " identified as botnet destinations")
    print("Total of " + str(len(botnet_dst_comms)) + " hosts communicating with botnet destinations")
    print(sorted(list(botnet_dst_comms)))


def main():
    flows, xs, ys = tp.tparse_combined(TRAINING_FILE_ALL, TRAINING_FILE_BOTNET, True, 5)

    test_flows = flows[:TEST_PARTITION_SIZE]
    test_x = np.array(xs[:TEST_PARTITION_SIZE])
    test_y = np.array([y[0] for y in ys][:TEST_PARTITION_SIZE])

    train_flows = flows[TEST_PARTITION_SIZE:]
    train_x = np.array(xs[TEST_PARTITION_SIZE:])
    train_y = np.array([y[0] for y in ys][TEST_PARTITION_SIZE:])

    print("Number of training flows: " + str(len(train_x)))
    print("Number of testing flows: " + str(len(test_x)))

    print('')
    print("Training decision tree:")
    train_DT(train_x, train_y, test_flows, test_x, test_y)
    print('')

    print('')
    print("Training random forest:")
    train_RF(train_x, train_y, test_flows, test_x, test_y)
    print('')

    print('')
    print("Training Naive Bayes:")
    train_NB(train_x, train_y, test_flows, test_x, test_y)

    #print('')
    #print("Training SVM:")
    #train_SVM(train_x, train_y, test_flows, test_x, test_y)
    #print('')

if __name__ == "__main__":
    main()
