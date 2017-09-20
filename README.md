# botd


<img src="https://i.imgur.com/PePvYrP.png" width="500" />

[demo](https://imgur.com/a/OMkbI)

A machine learning based **bot**net **d**etector that examines network flows generated over limited time intervals and reports LAN hosts most likely to be infected. Developed as part of a SURF research project at Caltech. More info: https://botnetsurf2017.wordpress.com/

This is a WIP, more info to come later!

Dependencies
------
* Python 2.7
* [Wireshark](https://www.wireshark.org/), for command line utilities `editcap` and `capinfos`
* [Argus](https://qosient.com/argus/downloads.shtml), for `ra` and `argus`
* The following Python packages:
  * Keras
  * Tensorflow
  * scikit-learn
  * matplotlib
  * PyQt4
  * pyqtgraph
  * numpy
  * scipy

Installing
------
Install the required dependencies, then clone this repository.

Datasets
------
The datasets we have worked with during development is the [CTU-13 Dataset](http://mcfp.weebly.com/the-ctu-13-dataset-a-labeled-dataset-with-botnet-normal-and-background-traffic.html).

Running in offline mode on some of the larger .pcaps is _very_ slow, due to the way `editcaps` is used to filter the packets in each interval, followed by `argus` and then `ra`. Versions of CTU-13 scenarios already split into .pcaps of 300 second intervals (with 150 second overlap between each interval) will be available to download and can be used to demonstrate the detector tool much faster.

Models
------
The current models use scikit-learn's RandomForestClassifier and are trained on flows generated over 300 second windows (and 150 second overlap between consecutive windows).

Additional models can be added by placing them into `/models` and will be loaded at runtime. Models can be removed by removing from the `/models/` folder, or by creating another folder called `unused` inside the models folder, and moving unused models there.

Usage
------
#### Online mode
(not yet implemented)

#### Offline mode

botd can run in offline mode and analyze an existing .pcap file by splitting it into time intervals. Upon selecting the .pcap file for offline mode, botd will first search for a folder in the same directory as the .pcap, with the same name as the .pcap. This folder contains the split .pcaps. If this folder does not exist, then botd will start a background thread which runs `editcap` and `argus` to generate the NetFlow files. Otherwise, it will attempt to use the existing .binetflow files.

The main interface of botd displays a list of models and a list of LAN host IP addresses. Selecting a model and an IP address will show a graph the number of predicted botnet flows that the selected IP address is involved in, as predicted by the selected model, over time. The score is a measure of how likely a host is to be infected - highly suspicious hosts will appear in red, while historically suspicious hosts appear in yellow.

Acknowledgements
------
"An empirical comparison of botnet detection methods" Sebastian Garcia, Martin Grill, Honza Stiborek and Alejandro Zunino. Computers and Security Journal, Elsevier. 2014. Vol 45, pp 100-123. http://dx.doi.org/10.1016/j.cose.2014.05.011
