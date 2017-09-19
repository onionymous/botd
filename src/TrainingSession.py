# SURF2017
# File: TrainingSession
# Created: 6/26/17
# Author: Stephanie Ding

import tensorflow as tf
import numpy as np
import random

TRAINING_FILE_NORMAL = "../datasets/9/normal.out"
TRAINING_FILE_BOTNET = "../datasets/9/botnet.out"

INPUT_DIMENSION = 40
HIDDEN_DIMENSION = 40
OUTPUT_DIMENSION = 1
BATCH_SIZE = 200
NUM_EPOCHS = 500
LEARNING_RATE = 0.0015
SAVE_STEP = 100
SAVE_FILE = "../tf"

def get_next_batch(l, batch_size):
    for i in range(0, len(l), batch_size):
        yield l[i:i + batch_size]

def main():
    # read the input data files
    xs = []
    ys = []
    with open(TRAINING_FILE_NORMAL, "r") as fin:
        for line in fin:
            xs.append([int(x) for x in line.split(',')[4:]])
            ys.append([0])

    with open(TRAINING_FILE_BOTNET, "r") as fin:
        for line in fin:
            xs.append([int(x) for x in line.split(',')[4:]])
            ys.append([1])

    all_data = list(zip(xs, ys))
    random.shuffle(all_data)

    test_set = all_data[:BATCH_SIZE]
    xs, ys = zip(*test_set)
    #xs = np.array(xs)
    #ys = np.array(ys)

    train_set = all_data[BATCH_SIZE:]

    # make a tensorflow graph
    x = tf.placeholder(tf.float32, [None, INPUT_DIMENSION])
    y = tf.placeholder(tf.float32, [None, OUTPUT_DIMENSION])

    # weights and biases
    w1 = tf.Variable(tf.random_normal([INPUT_DIMENSION, HIDDEN_DIMENSION], stddev=0.1))
    b1 = tf.Variable(tf.random_normal([HIDDEN_DIMENSION], stddev=0.1))

    w2 = tf.Variable(tf.random_normal([HIDDEN_DIMENSION, OUTPUT_DIMENSION], stddev=0.1))
    b2 = tf.Variable(tf.random_normal([OUTPUT_DIMENSION], stddev=0.1))

    # Construct model
    pred = tf.matmul(tf.matmul(x, w1) + b1, w2) + b2

    # Cost function
    loss_op = tf.nn.l2_loss(pred - y)
    avg_error = tf.reduce_mean(tf.abs(tf.subtract(pred, y)))

    # training operation
    lr = tf.Variable(LEARNING_RATE, trainable=False)
    training_op = tf.train.AdamOptimizer(lr).minimize(loss_op)

    # initialize all variables
    init = tf.global_variables_initializer()

    with tf.Session() as sess:
        sess.run(init)

        # Training cycle
        for epoch in range(NUM_EPOCHS):
            print("Epoch: " + str(epoch))
            batch = get_next_batch(train_set, BATCH_SIZE).next()
            batch_x, batch_y = zip(*batch)

            #batch_x = np.array(batch_x)
            #batch_y = np.array(batch_y)

            step = sess.run(training_op, feed_dict={x: batch_x, y: batch_y})

            if epoch % SAVE_STEP == 0:
                saver = tf.train.Saver()
                save_path = saver.save(sess, SAVE_FILE, global_step=epoch)
                print("Model saved in file: %s", save_path)

            loss = sess.run(loss_op, feed_dict={x: test_x, y: test_y})
            print("loss: " + str(loss))

        # After running
        print("\nOptimization finished!")
        print("Average error on test set: %s", str(sess.run(avg_error, feed_dict = {x: test_x, y:test_y})))

if __name__ == "__main__":
    main()