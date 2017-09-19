# SURF2017
# File: KerasTrain.py
# Created: 6/26/17
# Author: Stephanie Ding

import constants
from keras.models import Sequential
from keras.layers import Dense
from keras.callbacks import ModelCheckpoint
import numpy as np
import random

TRAINING_FILE_ALL = "../datasets/10/ds10_truncated.csv"
TRAINING_FILE_NORMAL = "../datasets/9/ds9_300_normal.csv"
TRAINING_FILE_BOTNET = "../datasets/9/ds9_300_botnet.csv"

MODEL_LOADPATH = "../models/ds9_300_model.hdf5"
MODEL_SAVEPATH = "../models/ds9_300_model.hdf5"

INPUT_DIMENSION = 40
HIDDEN_DIMENSION = 12
OUTPUT_DIMENSION = 1
NUM_EPOCHS = 200
BATCH_SIZE = 512
TEST_PARTITION_SIZE = 10000
RANDOM_SEED = 7

FILE_TO_PREDICT = "../datasets/9/separated_csvs/dataset9_00024_20110817050101.csv"

# fix random seed for reproducibility
np.random.seed(RANDOM_SEED)

def create_model():
    # create model
    model = Sequential()
    model.add(Dense(INPUT_DIMENSION, input_dim=INPUT_DIMENSION, activation='relu'))
    model.add(Dense(HIDDEN_DIMENSION, activation='relu'))
    model.add(Dense(OUTPUT_DIMENSION, activation='sigmoid'))
    return model

def train():
    botnet_flows = set()
    xs = []
    ys = []
    with open(TRAINING_FILE_BOTNET, "r") as fin:
        for line in fin:
            stats = line.split(',')
            flow_id = tuple(stats[:5])
            if flow_id[0] in constants.DATASET_9_INFECTED_HOSTS:
                botnet_flows.add(flow_id)
                xs.append([int(x) for x in stats[5:]])
                ys.append([1])

    print("Number of botnet flows: " + str(len(xs)))

    counter = 2*len(xs)
    with open(TRAINING_FILE_NORMAL, "r") as fin:
        for line in fin:
            if counter == 0:
                break
            stats = line.split(',')
            flow_id = tuple(stats[:5])
            xs.append([int(x) for x in stats[5:]])
            ys.append([0])
            counter -= 1

    # with open(TRAINING_FILE_ALL, "r") as fin:
    #     counter = 3*len(xs)
    #     for line in fin:
    #         stats = line.split(',')
    #         flow_id = tuple(stats[:5])
    #         if flow_id not in botnet_flows:
    #             xs.append([int(x) for x in stats[5:]])
    #             ys.append([0])
    #             counter -= 1
    #         if counter == 0:
    #             print("Number of total flows: " + str(len(xs)))
    #             break

    all_data = list(zip(xs, ys))
    random.shuffle(all_data)
    xs, ys = zip(*all_data)

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
    model = create_model()
    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
    model.fit(train_x, train_y, validation_split=0.2, epochs=NUM_EPOCHS, batch_size=BATCH_SIZE, callbacks=callbacks_list, verbose=2)

    # evaluate model with testing dataset
    print("Testing accuracy on unseen test dataset of size: " + str(len(test_x)))
    scores = model.evaluate(test_x, test_y)
    print("\n%s: %.2f%%" % (model.metrics_names[1], scores[1] * 100))

def predict(filename):
    # load csv
    flow_ids = []
    xs = []
    with open(filename, "r") as fin:
        for line in fin:
            stats = line.split(',')
            flow_id = tuple(stats[:5])
            flow_ids.append(flow_id)
            xs.append([int(x) for x in stats[5:]])

    xs = np.array(xs)

    # load model
    model = create_model()
    model.load_weights(MODEL_LOADPATH)
    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

    # predict
    errors = 0
    botnet_hosts = set()
    results = model.predict(xs)
    for n, i in enumerate(results):
        if int(i) == 1:
            #if flow_ids[n][0] not in constants.DATASET_9_INFECTED_HOSTS and flow_ids[n][2] not in constants.DATASET_9_INFECTED_HOSTS:
            #    errors += 1
            errors += 1
            botnet_hosts.add(flow_ids[n])

            #print("Identified: " + str(flow_ids[n]) + " as botnet flow")
    print("incorrectly identified " + str(errors) + "/" + str(len(results)) + " as botnet flows")
    print(botnet_hosts)

def main():
    # train()
    predict(FILE_TO_PREDICT)

if __name__ == "__main__":
    main()
