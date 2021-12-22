#!/usr/bin/python

# Importing libraries

# To display output from ML model
from prettytable import PrettyTable 
# To handle the Ryu output
import subprocess, sys
# For the timer
import signal
# For process handling
import os
# For training the model 
import numpy as np
#To use ML model in real-time
import pickle 

## command to run ##

# Path of simple_monitor
#cmd = "sudo ryu run /usr/local/lib/python2.7/dist-packages/ryu/app/simple_monitor_AK.py"
cmd = "sudo ryu run simple_monitor_13.py"

flows = {} #empty flow dictionary

#how long to collect training data
TIMEOUT = 15*60 #15 min 

class Flow:
    def __init__(self, time_start, datapath, inport, ethsrc, ethdst, outport, packets, bytes):
        self.time_start = time_start
        self.datapath = datapath
        self.inport = inport
        self.ethsrc = ethsrc
        self.ethdst = ethdst
        self.outport = outport
        
        #attributes for forward flow direction (source -> destination)
        self.forward_packets = packets
        self.forward_bytes = bytes
        self.forward_delta_packets = 0
        self.forward_delta_bytes = 0
        self.forward_inst_pps = 0.00
        self.forward_avg_pps = 0.00
        self.forward_inst_bps = 0.00
        self.forward_avg_bps = 0.00
        self.forward_status = 'ACTIVE'
        self.forward_last_time = time_start
        
        #attributes for reverse flow direction (destination -> source)
        self.reverse_packets = 0
        self.reverse_bytes = 0
        self.reverse_delta_packets = 0
        self.reverse_delta_bytes = 0
        self.reverse_inst_pps = 0.00
        self.reverse_avg_pps = 0.00
        self.reverse_inst_bps = 0.00
        self.reverse_avg_bps = 0.00
        self.reverse_status = 'INACTIVE'
        self.reverse_last_time = time_start
        
    # Updates the attributes in the forward flow direction
    def updateforward(self, packets, bytes, curr_time):
        self.forward_delta_packets = packets - self.forward_packets
        self.forward_packets = packets
        if curr_time != self.time_start: self.forward_avg_pps = packets/float(curr_time-self.time_start)
        if curr_time != self.forward_last_time: self.forward_inst_pps = self.forward_delta_packets/float(curr_time-self.forward_last_time)
        
        self.forward_delta_bytes = bytes - self.forward_bytes
        self.forward_bytes = bytes
        if curr_time != self.time_start: self.forward_avg_bps = bytes/float(curr_time-self.time_start)
        if curr_time != self.forward_last_time: self.forward_inst_bps = self.forward_delta_bytes/float(curr_time-self.forward_last_time)
        self.forward_last_time = curr_time
        
        if (self.forward_delta_bytes==0 or self.forward_delta_packets==0): #if the flow did not receive any packets of bytes
            self.forward_status = 'INACTIVE'
        else:
            self.forward_status = 'ACTIVE'

    # Updates the attributes in the reverse flow direction
    def updatereverse(self, packets, bytes, curr_time):
        self.reverse_delta_packets = packets - self.reverse_packets
        self.reverse_packets = packets
        if curr_time != self.time_start: self.reverse_avg_pps = packets/float(curr_time-self.time_start)
        if curr_time != self.reverse_last_time: self.reverse_inst_pps = self.reverse_delta_packets/float(curr_time-self.reverse_last_time)
        
        self.reverse_delta_bytes = bytes - self.reverse_bytes
        self.reverse_bytes = bytes
        if curr_time != self.time_start: self.reverse_avg_bps = bytes/float(curr_time-self.time_start)
        if curr_time != self.reverse_last_time: self.reverse_inst_bps = self.reverse_delta_bytes/float(curr_time-self.reverse_last_time)
        self.reverse_last_time = curr_time

        if (self.reverse_delta_bytes==0 or self.reverse_delta_packets==0): #if the flow did not receive any packets of bytes
            self.reverse_status = 'INACTIVE'
        else:
            self.reverse_status = 'ACTIVE'

# Function to print flow attributes and output of ML model to classify the flow
def printclassifier(model):
    x = PrettyTable()
    x.field_names = ["Flow ID", "Src MAC", "Dest MAC", "Traffic Type","Forward Status","Reverse Status"]

    for key,flow in flows.items():
        features = np.asarray([flow.forward_delta_packets,flow.forward_delta_bytes,flow.forward_inst_pps,flow.forward_avg_pps,flow.forward_inst_bps, flow.forward_avg_bps, flow.reverse_delta_packets,flow.reverse_delta_bytes,flow.reverse_inst_pps,flow.reverse_avg_pps,flow.reverse_inst_bps,flow.reverse_avg_bps]).reshape(1,-1) # Convert to array so the model can understand the features properly
        
        label = model.predict(features.tolist()) # If model is supervised (logistic regression) then the label is the type of traffic
        
        # If the model is unsupervised, the label is a cluster number. Refer to Jupyter notebook to see how cluster numbers map to labels
        if label == 0: label = ['dns']
        elif label == 1: label = ['game']
        elif label == 2: label = ['ping']
        elif label == 3: label = ['quake']  
        elif label == 4: label = ['telnet']
        elif label == 5: label = ['voice']
	
        
        x.add_row([key, flow.ethsrc, flow.ethdst, label[0],flow.forward_status,flow.reverse_status]) 
    print(x) # Print output in pretty mode (i.e. formatted table)

# Function to print flow attributes when collecting training data
def printflows(traffic_type,f):
    for key,flow in flows.items():

        outstring = '\t'.join([
        str(flow.forward_packets),
        str(flow.forward_bytes),
        str(flow.forward_delta_packets),
        str(flow.forward_delta_bytes), 
        str(flow.forward_inst_pps), 
        str(flow.forward_avg_pps),
        str(flow.forward_inst_bps), 
        str(flow.forward_avg_bps), 
        str(flow.reverse_packets),
        str(flow.reverse_bytes),
        str(flow.reverse_delta_packets),
        str(flow.reverse_delta_bytes),
        str(flow.reverse_inst_pps),
        str(flow.reverse_avg_pps),
        str(flow.reverse_inst_bps),
        str(flow.reverse_avg_bps),
        str(traffic_type)])
        f.write(outstring+'\n')
        
def run_ryu(p,traffic_type=None,f=None,model=None):
    ## run it ##
    time = 0
    while True:
        #print 'going through loop'
        out = p.stdout.readline()
        if out == '' and p.poll() != None:
            break
        if out != '' and out.startswith(b'data'): #when Ryu 'simple_monitor_AK.py' script returns output
            fields = out.split(b'\t')[1:] #split the flow details
            
            fields = [f.decode(encoding='utf-8', errors='strict') for f in fields] #decode flow details 
            
            unique_id = hash(''.join([fields[1],fields[3],fields[4]])) #create unique ID for flow based on switch ID, source host,and destination host
            if unique_id in flows.keys():
                flows[unique_id].updateforward(int(fields[6]),int(fields[7]),int(fields[0])) #update forward attributes with time, packet, and byte count
            else:
                rev_unique_id = hash(''.join([fields[1],fields[4],fields[3]])) #switch source and destination to generate same hash for src/dst and dst/src
                if rev_unique_id in flows.keys():
                    flows[rev_unique_id].updatereverse(int(fields[6]),int(fields[7]),int(fields[0])) #update reverse attributes with time, packet, and byte count
                else:
                    flows[unique_id] = Flow(int(fields[0]), fields[1], fields[2], fields[3], fields[4], fields[5], int(fields[6]), int(fields[7])) #create new flow object
            if not model is None:
                if time%10==0: #print output of model every 10 seconds
                    printclassifier(model)
            else:
                printflows(traffic_type,f) #for training data
        time += 1
 
#print help output in case of incorrect options 
def printHelp():
    print("\nUsage: sudo python traffic_classifier.py [subcommand] [options]")
    print("\n\tTo collect training data for a certain type of traffic, run: sudo python traffic_classifier.py train <TypeOfData>")
    print("\n\tTo start a near real time traffic classification application using unsupervised ML, run: sudo python traffic_classifier.py <NameOfAlgo>")
    print("\n\tTo start a near real time traffic classification application using supervised ML, run: sudo python traffic_classifier.py <NameOfAlgo>")
    print("\n\t Available algorithms Logistic Regression, K Means clustering, K nearest neighbors, Random Forest Classifier, SVM, Gaussian Naive Bayes")
    print("\n\t SUBCOMMANDS = ('train', 'logistic', 'kmeans', 'knearest', 'svm', 'Randomforest', 'gaussiannb')")
    return

#for timer to collect flow training data
def alarm_handler(signum, frame):
    print("Finished collecting data.")
    raise Exception()
    
if __name__ == '__main__':
    SUBCOMMANDS = ('train', 'logistic', 'kmeans', 'knearest', 'svm', 'Randomforest', 'gaussiannb')

    if len(sys.argv) < 2:
        print("ERROR: Incorrect # of args")
        print()
        printHelp()
        sys.exit();
    else:
        if len(sys.argv) == 2:
            if sys.argv[1] not in SUBCOMMANDS:
                print("ERROR: Unknown subcommand argument.")
                print("       Currently subaccepted commands are: %s" % str(SUBCOMMANDS).strip('()'))
                print()
                printHelp()
                sys.exit();

    if len(sys.argv) == 1:
        # Called with no arguments
        printHelp()
    elif len(sys.argv) >= 2:
        if sys.argv[1] == "train":
            if len(sys.argv) == 3:
                p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) #start Ryu process
                traffic_type = sys.argv[2]
                f = open(traffic_type+'_training_data.csv', 'w') #open training data output file
                signal.signal(signal.SIGALRM, alarm_handler) #start signal process
                signal.alarm(TIMEOUT) #set for 15 minutes
                try:
                    headers = 'Forward Packets\tForward Bytes\tDelta Forward Packets\tDelta Forward Bytes\tForward Instantaneous Packets per Second\tForward Average Packets per second\tForward Instantaneous Bytes per Second\tForward Average Bytes per second\tReverse Packets\tReverse Bytes\tDelta Reverse Packets\tDelta Reverse Bytes\tDeltaReverse Instantaneous Packets per Second\tReverse Average Packets per second\tReverse Instantaneous Bytes per Second\tReverse Average Bytes per second\tTraffic Type\n'
                    f.write(headers)
                    run_ryu(p,traffic_type=traffic_type,f=f)
                except Exception:
                    print('Exiting')
                    os.killpg(os.getpgid(p.pid), signal.SIGTERM) #kill ryu process on exit
                    f.close()
            else:
                print("ERROR: specify traffic type.\n")

        else:
            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT) #start ryu process
            if sys.argv[1] == 'logistic':
                infile = open('models/LogisticRegression','rb') 
            elif sys.argv[1] == 'kmeans':
                infile = open('models/KMeans_Clustering','rb')
            elif sys.argv[1] == 'svm':
                infile = open('models/SVC','rb')
            elif sys.argv[1] == 'kneighbors':
                infile = open('models/KNeighbors','rb')
            elif sys.argv[1] == 'Randomforest':
                infile = open('models/RandomForestClassifier','rb')
            elif sys.argv[1] == 'gaussiannb':
                infile = open('models/GaussianNB','rb')
	    

            model = pickle.load(infile) #unload previously trained ML model (refer to Jupyter notebook for details)
            infile.close()
            run_ryu(p,model=model)
    sys.exit();
