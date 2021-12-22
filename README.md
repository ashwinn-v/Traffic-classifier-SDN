# Traffic-classifier-SDN
A system that could classify DNS, Telnet, Ping, Voice, Game, and Video traffic flows based on packet and byte information simulated by the Distributed Internet Traffic Generator (D-ITG) tool in an Software Defined Network (SDN) based network topology with Open vSwitch (OVS) using machine learning algorithms such as Logistic regression,K-Means clustering,K nearest neighbours, SVC, Gaussian NB and Random Forest Classifier.

## Installation steps

#### D-IGT

```
https://github.com/jbucar/ditg
```


#### Mininet

```
http://mininet.org/download/
```

#### Open vSwitch

```
https://www.openvswitch.org/download/
```

#### Start Mininet topology

```
sudo mn --topo single,3 --mac --switch ovsk --controller remote

```
#### Start Real time prediction

```
python3 traffic_classifier_python3.py supervised 
```
