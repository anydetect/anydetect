#!/usr/bin/env python3

#version 1.0.0-pre01

import logging
import queue
import signal
import socket
import socketserver
import threading
import time
from collections import namedtuple

from netflow.ipfix import IPFIXTemplateNotRecognized
from netflow.utils import UnknownExportVersion, parse_packet
from netflow.v9 import V9TemplateNotRecognized

import pandas as pd
import datetime

from sklearn.preprocessing import RobustScaler
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor

import xgboost as xgb

from sklearn import metrics
import os.path
from pickle import load,dump
import json
import os
import schedule

ip_address = "127.0.0.1"
port = 2055

isInitialTrain = False
packeges_to_learn = 1000000 #Will collect qty of packeges to learn
#Folder where detected anomaly will be saved
saveAnomalyPath = "results"

file_path = 'white_list_ips.json' #File with white list ip addresses to disable act of active response 
white_list_ip_addresses = [] #List of white list ip addresses

#Retrain schedule settings
sceduled_df = pd.DataFrame(dtype=object)

#Period to get data for retraining in hours back to datetime.now
retrain_data_period = 2

#start retrain every in hours
start_retrain_every = 2

# Check whether the specified path exists or not
isExist = os.path.exists(saveAnomalyPath)



if not isExist:
    # Create a new directory because it does not exist
    os.makedirs(saveAnomalyPath)

if not os.path.exists('IsolationForestModel.pkl') or not os.path.exists('Model_scaler.pkl')\
     or not os.path.exists('LocalOutlayerModel.pkl') or not os.path.exists('XgbModel.pkl') :
    isInitialTrain=True

if isInitialTrain:
    scaler = RobustScaler()
    clf = IsolationForest(random_state=47,n_jobs=-1, contamination=0.05,n_estimators=100,warm_start=True)
    lof = LocalOutlierFactor(n_jobs=-1, n_neighbors=20, contamination=0.001,novelty=True)
    xgb_classifier = xgb.XGBClassifier(objective='binary:logistic', n_estimators=500, random_state=42)
else:
    # Load scaler
    with open("Model_scaler.pkl", "rb") as f:
        scaler = load(f)
    
    # Load model
    with open("IsolationForestModel.pkl", "rb") as f:
        clf = load(f)

    # Load model
    with open("LocalOutlayerModel.pkl", "rb") as f:
        lof = load(f)

     # Load model
    with open("XgbModel.pkl", "rb") as f:
        xgb_classifier = load(f)

RawPacket = namedtuple('RawPacket', ['ts', 'client', 'data'])
ParsedPacket = namedtuple('ParsedPacket', ['ts', 'client', 'export'])

# Amount of time to wait before dropping an undecodable ExportPacket
PACKET_TIMEOUT = 60 * 60


logger = logging.getLogger("netflow-collector")
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)

def read_ips_from_file():
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            data = json.load(file)
            ip_addresses = [entry['ip'] for entry in data]
        return ip_addresses
    else:
        return []

white_list_ip_addresses = read_ips_from_file() #Getting white list ip addresses

print(white_list_ip_addresses)

class QueuingRequestHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]  # get content, [1] would be the socket
        self.server.queue.put(RawPacket(time.time(), self.client_address, data))
        logger.debug(
            "Received %d bytes of data from %s", len(data), self.client_address
        )


class QueuingUDPListener(socketserver.ThreadingUDPServer):
    """A threaded UDP server that adds a (time, data) tuple to a queue for
    every request it sees
    """

    def __init__(self, interface, queue):
        self.queue = queue

        # If IPv6 interface addresses are used, override the default AF_INET family
        if ":" in interface[0]:
            self.address_family = socket.AF_INET6

        super().__init__(interface, QueuingRequestHandler)

class ThreadedNetflowCollectProcessor(threading.Thread):
    
    def __init__(self,queue):
        self.queue_out = queue
        self._shutdown = threading.Event()
        super().__init__()

    def run(self):
        while not self._shutdown.is_set():
            try:
                # 0.5s delay to limit CPU usage while waiting for new packets
                pkt = self.queue_out.get(block=True, timeout=0.5)  # type: df
            except queue.Empty:
                continue

            self.collect_data_to_next_train(pkt)


    def collect_data_to_next_train(self, pkt):
        global sceduled_df

        inc_df = pd.DataFrame(pkt,dtype=object)
        inc_df['date'] = pd.to_datetime(datetime.datetime.now())
        sceduled_df = pd.concat([sceduled_df, inc_df])

    
    def stop(self):
        logger.info("Shutting down Collect Processor")
        self._shutdown.set()

    def join(self, timeout=None):
        super().join(timeout=timeout)


        
class ThreadedNetFlowPredictProcessor(threading.Thread):
    def __init__(self):
        self.input_process_q = queue.Queue()
        self.output_process_q = queue.Queue()
        self.collect_process = ThreadedNetflowCollectProcessor(self.output_process_q)
        self.collect_process.start()
        self._shutdown = threading.Event()
        super().__init__()

    def run(self):
        def predict_model(model, data):
            return model.predict(data)
    
        try:
            global clf, lof
            while not self._shutdown.is_set():
                try:
                    pkt = self.input_process_q.get(block=True, timeout=0.5)
                except queue.Empty:
                    continue
                df_load = pd.DataFrame(pkt, dtype=object)
                norm_data = self.normalize_data(df_load)
                
                models = [clf, lof, xgb_classifier]
                results = [None] * len(models)
                threads = [
                    threading.Thread(target=lambda i, model: results.__setitem__(i, predict_model(model, norm_data)), args=(i, model))
                    for i, model in enumerate(models)
                ]
                
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join()
                
                result_isf, result_lof, result_xgb = results
                
                if any(len(result[result == -1]) > 0 for result in [result_isf, result_lof]) or len(result_xgb[result_xgb == 1]) > 0:
                    df_load['predict_isf'] = result_isf
                    df_load['predict_lof'] = result_lof
                    df_load['predict_xgb'] = result_xgb
                    self.do_action(df_load)
                    clf.n_estimators += 1
                    clf.fit(norm_data, [1])
                else:
                    clf.n_estimators += 1
                    clf.fit(norm_data, [0])
                    self.output_process_q.put(pkt)
        finally:
            self.collect_process.stop()
            self._shutdown.set()


    #This method can do some work when anomaly is detected
    def do_action(self, anomaly_details):
        print('Anomaly detected at:')
        print(anomaly_details)
        ip_address = anomaly_details[0][0] #'IPV4_SRC_ADDR'

        if ip_address not in white_list_ip_addresses:
            self.write_to_file(anomaly_details)
        else:
            print(f'IP address {ip_address} is in the white list. No action needed.')

    def write_to_file(self, anomaly_details):
        data = {}
        data['IPV4_SRC_ADDR']=str(anomaly_details[0][0])
        data['SRC_PORT']=str(anomaly_details[1][0])
        data['IPV4_DST_ADDR']=str(anomaly_details[2][0])
        data['DST_PORT']=str(anomaly_details[3][0])
        data['Predict_ISF']=str(anomaly_details['predict_isf'][0])
        data['Predict_LOF']=str(anomaly_details['predict_lof'][0])

        with open("{path}/{date:%d_%m_%Y_%H_%M_%S}.json".format(date=datetime.datetime.now(),path=saveAnomalyPath), 'w', encoding='utf-8') as jsonf:
            jsonf.write(json.dumps(data, indent=4))

    def normalize_data(self, df):
        global scaler

        df_to_scale = df.drop([0, 2, 4] ,axis=1)
        num_cols = df_to_scale.columns
        
        scaler_temp = scaler.transform(df_to_scale)

        std_df = pd.DataFrame(scaler_temp, columns = num_cols)

        std_df.dropna(inplace=True)

        return std_df

    def put(self, inc_df):
        self.input_process_q.put(inc_df)

    def stop(self):
        logger.info("Shutting down Predict Processor")
        self.collect_process.stop()
        self._shutdown.set()
        

    def join(self, timeout=None):
        self.collect_process.join(timeout=timeout)
        super().join(timeout=timeout)


class ThreadedNetFlowListener(threading.Thread):
    """A thread that listens for incoming NetFlow packets, processes them, and
    makes them available to consumers.

    - When initialized, will start listening for NetFlow packets on the provided
      host and port and queuing them for processing.
    - When started, will start processing and parsing queued packets.
    - When stopped, will shut down the listener and stop processing.
    - When joined, will wait for the listener to exit

    For example, a simple script that outputs data until killed with CTRL+C:
    >>> listener = ThreadedNetFlowListener('0.0.0.0', 2055)
    >>> print("Listening for NetFlow packets")
    >>> listener.start() # start processing packets
    >>> try:
    ...     while True:
    ...         ts, export = listener.get()
    ...         print("Time: {}".format(ts))
    ...         for f in export.flows:
    ...             print(" - {IPV4_SRC_ADDR} sent data to {IPV4_DST_ADDR}"
    ...                   "".format(**f))
    ... finally:
    ...     print("Stopping...")
    ...     listener.stop()
    ...     listener.join()
    ...     print("Stopped!")
    """

    def __init__(self, host: str, port: int):
        logger.info("Starting the NetFlow listener on {}:{}".format(host, port))
        self.output = queue.Queue()
        self.input = queue.Queue()
        self.server = QueuingUDPListener((host, port), self.input)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self._shutdown = threading.Event()
        super().__init__()

    def get(self, block=True, timeout=None) -> ParsedPacket:
        """Get a processed flow.

        If optional args 'block' is true and 'timeout' is None (the default),
        block if necessary until a flow is available. If 'timeout' is
        a non-negative number, it blocks at most 'timeout' seconds and raises
        the queue.Empty exception if no flow was available within that time.
        Otherwise ('block' is false), return a flow if one is immediately
        available, else raise the queue.Empty exception ('timeout' is ignored
        in that case).
        """
        return self.output.get(block, timeout)

    def run(self):
        # Process packets from the queue
        try:
            # TODO: use per-client templates
            templates = {"netflow": {}, "ipfix": {}}
            to_retry = []
            while not self._shutdown.is_set():
                try:
                    # 0.5s delay to limit CPU usage while waiting for new packets
                    pkt = self.input.get(block=True, timeout=0.5)  # type: RawPacket
                except queue.Empty:
                    continue

                try:
                    # templates is passed as reference, updated in V9ExportPacket
                    export = parse_packet(pkt.data, templates)
                except UnknownExportVersion as e:
                    logger.error("%s, ignoring the packet", e)
                    continue
                except (V9TemplateNotRecognized, IPFIXTemplateNotRecognized):
                    # TODO: differentiate between v9 and IPFIX, use separate to_retry lists
                    if time.time() - pkt.ts > PACKET_TIMEOUT:
                        logger.warning("Dropping an old and undecodable v9/IPFIX ExportPacket")
                    else:
                        to_retry.append(pkt)
                        logger.debug("Failed to decode a v9/IPFIX ExportPacket - will "
                                     "re-attempt when a new template is discovered")
                    continue

                if export.header.version == 10:
                    logger.debug("Processed an IPFIX ExportPacket with length %d.", export.header.length)
                else:
                    logger.debug("Processed a v%d ExportPacket with %d flows.",
                                 export.header.version, export.header.count)

                # If any new templates were discovered, dump the unprocessable
                # data back into the queue and try to decode them again
                if export.header.version in [9, 10] and export.contains_new_templates and to_retry:
                    logger.debug("Received new template(s)")
                    logger.debug("Will re-attempt to decode %d old v9/IPFIX ExportPackets", len(to_retry))
                    for p in to_retry:
                        self.input.put(p)
                    to_retry.clear()

                self.output.put(ParsedPacket(pkt.ts, pkt.client, export))
        finally:
            # Only reached when while loop ends
            self.server.shutdown()
            self.server.server_close()

    def stop(self):
        logger.info("Shutting down the NetFlow listener")
        self._shutdown.set()

    def join(self, timeout=None):
        self.thread.join(timeout=timeout)
        super().join(timeout=timeout)

def standartize_process(df):
    global scaler

    df_to_scale = df.drop([0, 2, 4] ,axis=1)
    num_cols = df_to_scale.columns
    
    scaler.fit(df_to_scale)
    scaler_temp = scaler.transform(df_to_scale)

    if not os.path.exists('Model_scaler.pkl'):
        with open("Model_scaler.pkl", "wb") as f:
            dump(scaler, f, protocol=5)

    std_df = pd.DataFrame(scaler_temp, columns = num_cols)

    std_df.dropna(inplace=True)

    return std_df


#Re train new model in separate thread
def do_train_job(df_data):
    global clf
    global lof
    global xgb_classifier

    standartized_data= standartize_process(df_data.drop(['date'] ,axis=1))

    print("Start retrain Thread")
    X = standartized_data
    y = lst = [0] * len(standartized_data)

    clf_new = IsolationForest(random_state=47,n_jobs=-1, contamination=0.05,n_estimators=1000,warm_start=True)
    lof_new = LocalOutlierFactor(n_jobs=-1, n_neighbors=20, contamination=0.01,novelty=True)
    xgb_classifier_new = xgb.XGBClassifier(objective='binary:logistic', n_estimators=500, random_state=42)

    clf_new.fit(X)
    lof_new.fit(X)
    xgb_classifier_new.fit(X, y)

    with open("IsolationForestModel.pkl", "wb") as f:
        dump(clf_new, f, protocol=5)

    with open("LocalOutlayerModel.pkl", "wb") as f:
        dump(lof_new, f, protocol=5)
    
    with open("XgbModel.pkl", "wb") as f:
        dump(xgb_classifier_new, f, protocol=5)

    #Replace  main model to new trained model
    clf = clf_new
    lof = lof_new
    xgb_classifier = xgb_classifier_new
    print("Finish retrain Thread")
    
#Method to train if first time is started
def initial_train_predict(raw_data):
       
    df_load = pd.DataFrame(raw_data,dtype=object)
    
    standartized_data= standartize_process(df_load)
    
    X = standartized_data
    y = lst = [0] * len(standartized_data)
      
    start = time.time()
    
    clf.fit(X)
    lof.fit(X)
    xgb_classifier.fit(X,y)

    end = time.time()
    print('Time taken to train: {0}'.format(end - start))
    
    with open("IsolationForestModel.pkl", "wb") as f:
        dump(clf, f, protocol=5)

    with open("LocalOutlayerModel.pkl", "wb") as f:
        dump(lof, f, protocol=5)

    with open("XgbModel.pkl", "wb") as f:
        dump(xgb_classifier, f, protocol=5)

    result_isf = clf.predict(X)
    result_lof = lof.predict(X)
    result_xgb = xgb_classifier.predict(X)
    
    standartized_data['label']=1
    y_label = standartized_data['label'].values
    y_label = y_label.astype('int')

    print("Validate Isolation Forest model")
    validate(y_label,result_isf)

    print("Validate Local Outlayer factor model")
    validate(y_label,result_lof)

    print("Validate XGBoost factor model")
    validate(y,result_xgb)
        

#Validation result for trained data
def validate(y,result):
    test_accuracy = metrics.accuracy_score(y,result)
    print("Validation score after training is: {0}".format(test_accuracy*100))

#Method which scheduler starts 
def start_retrain_thread():
    global sceduled_df
    global white_list_ip_addresses

    white_list_ip_addresses = read_ips_from_file() #Reload white list ip addresses

    if sceduled_df.empty:
        print('DataFrame for scheduled train is empty!')
    else:
        mask = (sceduled_df['date'] >= datetime.datetime.now() + datetime.timedelta(hours=-abs(retrain_data_period))) & (sceduled_df['date'] <= datetime.datetime.now())
        sceduled_df = sceduled_df.loc[mask]

        thread = threading.Thread(target = do_train_job, args=(sceduled_df,))
        thread.start()

   


def start_listening():
    listener = ThreadedNetFlowListener(ip_address, port)
    predictor = ThreadedNetFlowPredictProcessor()

    schedule.every(start_retrain_every).hours.do(start_retrain_thread)

    print("Listening for NetFlow packets")

    listener.start() # start processing packets
    predictor.start() # start predict process
    try:
        while True:
            #run scheduler panding
            schedule.run_pending()
            _, _, export = listener.get()
            nf_version = export.header.version
            for f in export.flows:
                isValidPkg = False

                if nf_version==5 and 'SRC_PORT' in f.data:
                    duration = f.data['LAST_SWITCHED'] - f.data['FIRST_SWITCHED']
                    isValidPkg=True
                    inc_data="{IPV4_SRC_ADDR},{SRC_PORT},{IPV4_DST_ADDR},{DST_PORT},{PROTO},{INPUT},{OUTPUT},{IN_PACKETS},{IN_OCTETS},{TCP_FLAGS},{fduration},{fversion}".format(**f.data,fduration=duration,fversion=nf_version)
                elif nf_version==9 and 'NF_F_FLOW_CREATE_TIME_MSEC' in f.data:
                    duration = f.data['NF_F_FLOW_CREATE_TIME_MSEC'] - f.data['NF_F_FLOW_CREATE_TIME_MSEC']
                    isValidPkg=True
                    inc_data="{IPV4_SRC_ADDR},{L4_SRC_PORT},{IPV4_DST_ADDR},{L4_DST_PORT},{PROTOCOL},{IN_BYTES},{OUT_BYTES},{IN_PKTS},{OUT_PKTS},0,{fduration},{fversion}".format(**f.data,fduration=duration,fversion=nf_version)
                
                elif nf_version>5 and 'L4_SRC_PORT' in f.data:
                    duration = f.data['LAST_SWITCHED'] - f.data['FIRST_SWITCHED']
                    isValidPkg=True
                    inc_data="{IPV4_SRC_ADDR},{L4_SRC_PORT},{IPV4_DST_ADDR},{L4_DST_PORT},{PROTOCOL},{IN_BYTES},{OUT_BYTES},{IN_PKTS},{OUT_PKTS},0,{fduration},{fversion}".format(**f.data,fduration=duration,fversion=nf_version)
                        
                if isValidPkg:
                    predictor.put([inc_data.split(',')])

    finally:
        print("Stopping...")
        listener.stop()
        listener.join()
        predictor.stop()
        predictor.join()
        print("Stopped!")    


if __name__ == "netflow.collector":
    logger.error("The collector is currently meant to be used as a CLI tool only.")
    
if __name__ == "__main__":
    
    try:
        if isInitialTrain:
            collected_packeges=[]
            listener_train = ThreadedNetFlowListener(ip_address, port)
            print("Listening for NetFlow packets to train")
            listener_train.start() # start processing packets

            try:
                start = time.time()
                while True:
                    ts, client, export = listener_train.get()
                    nf_version = export.header.version
                    for f in export.flows:
                        isValidPkg = False

                        if nf_version==5 and 'SRC_PORT' in f.data:
                            duration = f.data['LAST_SWITCHED'] - f.data['FIRST_SWITCHED']
                            isValidPkg=True
                            inc_data="{IPV4_SRC_ADDR},{SRC_PORT},{IPV4_DST_ADDR},{DST_PORT},{PROTO},{INPUT},{OUTPUT},{IN_PACKETS},{IN_OCTETS},{TCP_FLAGS},{fduration},{fversion}".format(**f.data,fduration=duration,fversion=nf_version)
                        elif nf_version==9 and 'NF_F_FLOW_CREATE_TIME_MSEC' in f.data:
                            duration = f.data['NF_F_FLOW_CREATE_TIME_MSEC'] - f.data['NF_F_FLOW_CREATE_TIME_MSEC']
                            isValidPkg=True
                            inc_data="{IPV4_SRC_ADDR},{L4_SRC_PORT},{IPV4_DST_ADDR},{L4_DST_PORT},{PROTOCOL},{IN_BYTES},{OUT_BYTES},{IN_PKTS},{OUT_PKTS},0,{fduration},{fversion}".format(**f.data,fduration=duration,fversion=nf_version)
                        
                        elif nf_version>5 and 'L4_SRC_PORT' in f.data:
                            duration = f.data['LAST_SWITCHED'] - f.data['FIRST_SWITCHED']
                            isValidPkg=True
                            inc_data="{IPV4_SRC_ADDR},{L4_SRC_PORT},{IPV4_DST_ADDR},{L4_DST_PORT},{PROTOCOL},{IN_BYTES},{OUT_BYTES},{IN_PKTS},{OUT_PKTS},0,{fduration},{fversion}".format(**f.data,fduration=duration,fversion=nf_version)
                        if len(collected_packeges)<=packeges_to_learn and isValidPkg:
                            #print('Add packege to learn')
                            collected_packeges.append(inc_data.split(','))
                            
                    if len(collected_packeges)>packeges_to_learn:
                        end = time.time()
                        print('Time taken to collect packages: {0}'.format(end - start))
                        print('Packages to train: {0}'.format(len(collected_packeges)))
                        break
            finally:
                print("Stopping collecting and begin training")
                listener_train.stop()
                listener_train.join()

                if len(collected_packeges)>0:
                    initial_train_predict(collected_packeges)
                    collected_packeges.clear()
                    print("Training Finished!")
                    print("-----------------")
                    print("Begin listening and analysing thread !!")
                    isInitialTrain=False

                    start_listening()
                else:
                    print("Packeges to train are null please restart")

        else:
            start_listening()  

    except KeyboardInterrupt:
        logger.info("Received KeyboardInterrupt, passing through")
    pass