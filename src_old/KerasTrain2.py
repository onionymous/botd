# SURF2017
# File: KerasTrain.py
# Created: 6/26/17
# Author: Stephanie Ding

import constants
import FlowParser as tp
from collections import Counter
from keras import backend as K
from keras.models import Sequential
from keras.layers import Dense
from keras.callbacks import ModelCheckpoint
import numpy as np
import random

TRAINING_FILE_ALL = "../datasets/9/capture20110817.truncated_flows.txt"
TRAINING_FILE_NORMAL = "../datasets/9/ds9_300_normal.csv"
TRAINING_FILE_BOTNET = "../datasets/9/botnet-capture-20110817-bot_flows.txt"

MODEL_LOADPATH = "../models/ds9_tmodel98.hdf5"
MODEL_SAVEPATH = "../models/ds9_tmodel.hdf5"

HIDDEN_DIMENSION = 20
OUTPUT_DIMENSION = 1
NUM_EPOCHS = 300
BATCH_SIZE = 1024
TEST_PARTITION_SIZE = 50000
RANDOM_SEED = 7

FILE_TO_PREDICT = "../datasets/9/T_all_flows/flows/dataset9_00046_20110817065101_flows.txt"

# fix random seed for reproducibility
np.random.seed(RANDOM_SEED)

def create_model(num_features):
    # create model
    model = Sequential()
    model.add(Dense(num_features, input_dim=num_features, activation='relu'))
    model.add(Dense(HIDDEN_DIMENSION, activation='relu'))
    model.add(Dense(OUTPUT_DIMENSION, activation='sigmoid'))
    return model

def train():
    flows, xs, ys = tp.tparse_combined(TRAINING_FILE_ALL, TRAINING_FILE_BOTNET, True, 5)

    test_flows = flows[:TEST_PARTITION_SIZE]
    test_x = np.array(xs[:TEST_PARTITION_SIZE])
    test_y = np.array(ys[:TEST_PARTITION_SIZE])

    train_x = np.array(xs[TEST_PARTITION_SIZE:])
    train_y = np.array(ys[TEST_PARTITION_SIZE:])

    print("Number of training flows: " + str(len(train_x)))
    print("Number of testing flows: " + str(len(test_x)))

    # checkpoint
    checkpoint = ModelCheckpoint(MODEL_SAVEPATH, monitor='val_acc', verbose=1, save_best_only=True, mode='max')
    callbacks_list = [checkpoint]

    # train model
    model = create_model(train_x.shape[1])
    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
    model.fit(train_x, train_y, validation_split=0.1, epochs=NUM_EPOCHS, batch_size=BATCH_SIZE, callbacks=callbacks_list, verbose=2)

    predict2(model, test_flows, test_x, test_y)

def predict(filename):
    # load csv
    flow_ids, xs = tp.tparse_single(filename)
    #xs, ys = tp.tparse_combined("../datasets/10/capture20110818.truncated_flows.txt", "../datasets/10/botnet-capture-20110818-bot_flows.txt", True, 9)
    #xs = np.array(xs)
    #ys = np.array(ys)

    # load model
    model = create_model(xs.shape[1])
    #print(xs.shape[1])
    model.load_weights(MODEL_LOADPATH)
    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

    # predict
    errors = 0
    botnet_hosts = set()
    results = model.predict(xs)
    for n, i in enumerate(results):
        if int(i) == 1:
            if flow_ids[n][2] not in constants.DATASET_9_INFECTED_HOSTS and flow_ids[n][5] not in constants.DATASET_9_INFECTED_HOSTS:
                errors += 1
            #errors += 1
            botnet_hosts.add(flow_ids[n])
            #print("Identified: " + str(flow_ids[n]) + " as botnet flow")
        else:
            if flow_ids[n][2] in constants.DATASET_9_INFECTED_HOSTS:
                errors += 1
    #print("incorrectly identified " + str(errors) + "/" + str(len(results)) + " as botnet flows")
    print(botnet_hosts)
    print("identified incorrectly: " + str(errors) + "/" + str(len(xs)) + " flows")

    # print("Testing accuracy on unseen test dataset of size: " + str(len(xs)))
    # scores = model.evaluate(xs, ys)
    # print("\n%s: %.2f%%" % (model.metrics_names[1], scores[1] * 100))

def predict2(model, test_flows, test_x, test_y):
    # evaluate model with testing dataset
    print("Testing accuracy on unseen test dataset of size: " + str(len(test_x)))
    #scores = model.evaluate(test_x, test_y)
    #print("\n%s: %.2f%%" % (model.metrics_names[1], scores[1] * 100))

    predicted = model.predict(test_x)
    #acc = K.mean(K.equal(test_y, K.round(predicted)))

    #print("acc: " + str(acc))

    # print("True positive: " + str(TP))
    # print("False positive: " + str(FP))
    # print("False negative: " + str(FN))
    # print("True negative: " + str(TN))

    get_hosts_statistics(test_flows, predicted)

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
        src, dst = tp.get_src_dst(flows[i])
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
            if dst in botnet_dsts and not dst.startswith(network_prefix):
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
        src, dst = tp.get_src_dst(flows[i])
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

def main():
    #train()
    model = create_model(xs.shape[1])
    # print(xs.shape[1])
    model.load_weights(MODEL_LOADPATH)
    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
    predict2(FILE_TO_PREDICT)

if __name__ == "__main__":
    main()
