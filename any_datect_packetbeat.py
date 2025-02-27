#!/usr/bin/env python3

# version 0.1.1-pre01

import logging
import queue
import threading
import time
import pandas as pd
import datetime
from sklearn.preprocessing import RobustScaler, OneHotEncoder
from sklearn.ensemble import IsolationForest
from sklearn import metrics
import os
from pickle import load, dump
import json
import schedule
from confluent_kafka import Consumer, KafkaException

kafka_ip_address = 'localhost:9092'
kafka_topic_name = 'demo'

isInitialTrain = False
packeges_to_learn = 100000  # Will collect qty of packages to learn
saveAnomalyPath = "results"  # Folder where detected anomaly will be saved

file_path = 'allow_list_ips.json'  # File with whitelist IP addresses to disable act of active response
allow_list_ip_addresses = []  # List of whitelist IP addresses

# Retrain schedule settings
sceduled_df = pd.DataFrame(dtype=object)

#Period to get data for retraining in hours back to datetime.now
retrain_data_period = 12

#start retrain every in hours
start_retrain_every = 1

# Check whether the specified path exists or not
isExist = os.path.exists(saveAnomalyPath)

if not isExist:
    # Create a new directory because it does not exist
    os.makedirs(saveAnomalyPath)

if not os.path.exists('IsolationForestModel.pkl') or not os.path.exists('Model_scaler.pkl') or not os.path.exists('Model_encoder.pkl'):
    isInitialTrain=True

if isInitialTrain:
    scaler = RobustScaler()
    encoder = OneHotEncoder(sparse_output=False)

    clf = IsolationForest(random_state=47,n_jobs=-1, contamination=0.05,n_estimators=1000,warm_start=True)
else:
    # Load scaler
    with open("Model_scaler.pkl", "rb") as f:
        scaler = load(f)
    
    # Load scaler
    with open("Model_encoder.pkl", "rb") as f:
        encoder = load(f)
    
    # Load model
    with open("IsolationForestModel.pkl", "rb") as f:
        clf = load(f)

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

allow_list_ip_addresses = read_ips_from_file() #Getting white list ip addresses

print(allow_list_ip_addresses)


class NetflowCollectProcessor(threading.Thread):
    
    def __init__(self, queue):
        self.queue_out = queue
        self._shutdown = threading.Event()
        super().__init__()

    def run(self):
        print("Start collector")
        while not self._shutdown.is_set():
            try:
                # 0.5s delay to limit CPU usage while waiting for new packets
                pkt = self.queue_out.get(block=True, timeout=0.1)  # type: df
                #print(pkt)
            except queue.Empty:
                continue

            self.collect_data_to_next_train(pkt)

    def collect_data_to_next_train(self, pkt):
        global sceduled_df

        inc_df = pd.DataFrame(pkt, dtype=object)
        inc_df['date'] = pd.to_datetime(datetime.datetime.now())
        sceduled_df = pd.concat([sceduled_df, inc_df])

    def stop(self):
        logger.info("Shutting down Collect Processor")
        self._shutdown.set()

class NetFlowPredictProcessor(threading.Thread):
    def __init__(self):
        self.input_process_q = queue.Queue()
        self.output_process_q = queue.Queue()
        self.collect_process = NetflowCollectProcessor(self.output_process_q)
        self.collect_process.start()
        self._shutdown = threading.Event()
        super().__init__()

    def predict_model(self,model, data):
            return model.predict(data)

    def run(self):
        try:
            global clf
            while not self._shutdown.is_set():
                try:
                    pkt = self.input_process_q.get(block=True, timeout=0.5)
                except queue.Empty:
                    continue
                df_load = pd.DataFrame(pkt, dtype=object)
                norm_data = self.normalize_data(df_load)

                result =  self.predict_model(clf, norm_data)
                
                #print(result[0])
                if result[0] == -1:
                    print("Anomaly detected")
                    df_load['predict_isf'] = result[0]

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
        
        ip_address = anomaly_details[0][0] #'IPV4_SRC_ADDR'
        host_name = anomaly_details[4][0] #'HOST_NAME'

        print('Anomaly detected at:')
        print(f'Host {host_name} : IP address {ip_address}')
        print('----------------------------------')

        if ip_address not in allow_list_ip_addresses:
            self.write_to_file(anomaly_details)
        else:
            print(f'Host {host_name} : IP address {ip_address}  is in the allow list. No action needed.')

    def write_to_file(self, anomaly_details):
        data = {}
        data['HOST_NAME']=str(anomaly_details[4][0])
        data['IPV4_SRC_ADDR']=str(anomaly_details[0][0])
        data['SRC_PORT']=str(anomaly_details[1][0])
        data['IPV4_DST_ADDR']=str(anomaly_details[2][0])
        data['DST_PORT']=str(anomaly_details[3][0])
        data['Predict_ISF']=str(anomaly_details['predict_isf'][0])

        with open("{path}/{date:%d_%m_%Y_%H_%M_%S}.json".format(date=datetime.datetime.now(),path=saveAnomalyPath), 'w', encoding='utf-8') as jsonf:
            jsonf.write(json.dumps(data, indent=4))

    def normalize_data(self, df):
        global scaler
        global encoder

        # Преобразование категориальных признаков
        categorical_features = [4, 5]  # Индексы категориальных признаков
        df_categorical = df.iloc[:, categorical_features]
        df_categorical_encoded = encoder.transform(df_categorical)

        # Нормализация числовых признаков
        df_to_scale = df.drop([0, 2, 4, 5] ,axis=1)
        num_cols = df_to_scale.columns
        scaler_temp = scaler.transform(df_to_scale)
        df_scaled = pd.DataFrame(scaler_temp, columns=num_cols)

        # Объединение нормализованных числовых и закодированных категориальных признаков
        df_final = pd.concat([pd.DataFrame(df_categorical_encoded), df_scaled], axis=1)
        df_final.dropna(inplace=True)

        return df_final

    def put(self, inc_df):
        self.input_process_q.put(inc_df)

    def stop(self):
        logger.info("Shutting down Predict Processor")
        self.collect_process.stop()
        self._shutdown.set()
        

    def join(self, timeout=None):
        self.collect_process.join(timeout=timeout)
        super().join(timeout=timeout)



def standartize_process(df):
    global scaler
    global encoder

    # Преобразование категориальных признаков
    categorical_features = [4,5]  # Индексы категориальных признаков
    df_categorical = df.iloc[:, categorical_features]
    df_categorical_encoded = encoder.fit_transform(df_categorical)

    df_to_scale = df.drop([0, 2, 4, 5] ,axis=1)

    # Нормализация числовых признаков
    num_cols = df_to_scale.columns
    scaler.fit(df_to_scale)
    scaler_temp = scaler.transform(df_to_scale)
    df_scaled = pd.DataFrame(scaler_temp, columns=num_cols)

    # Объединение нормализованных числовых и закодированных категориальных признаков
    df_final = pd.concat([pd.DataFrame(df_categorical_encoded), df_scaled], axis=1)
    df_final.dropna(inplace=True)

    if not os.path.exists('Model_scaler.pkl'):
        with open("Model_scaler.pkl", "wb") as f:
            dump(scaler, f, protocol=5)
    
    if not os.path.exists('Model_encoder.pkl'):
        with open("Model_encoder.pkl", "wb") as f:
            dump(encoder, f, protocol=5)

    return df_final

#Re train new model in separate thread
def do_train_job(df_data):
    global clf

    standartized_data= standartize_process(df_data.drop(['date'] ,axis=1))

    print("Start retrain Thread")
    X = standartized_data

    clf_new = IsolationForest(random_state=47,n_jobs=-1, contamination=0.05,n_estimators=1000,warm_start=True)

    clf_new.fit(X)

    with open("IsolationForestModel.pkl", "wb") as f:
        dump(clf_new, f, protocol=5)

    #Replace  main model to new trained model
    clf = clf_new

    
#Method to train if first time is started
def initial_train_predict(raw_data):
       
    df_load = pd.DataFrame(raw_data,dtype=object)
    
    standartized_data= standartize_process(df_load)
    
    X = standartized_data
    y = lst = [0] * len(standartized_data)
      
    start = time.time()
    
    clf.fit(X)


    end = time.time()
    print('Time taken to train: {0}'.format(end - start))
    
    with open("IsolationForestModel.pkl", "wb") as f:
        dump(clf, f, protocol=5)

    result_isf = clf.predict(X)
    
    standartized_data['label']=1
    y_label = standartized_data['label'].values
    y_label = y_label.astype('int')

    print("Validate Isolation Forest model")
    validate(y_label,result_isf)

        
#Validation result for trained data
def validate(y,result):
    test_accuracy = metrics.accuracy_score(y,result)
    print("Validation score after training is: {0}".format(test_accuracy*100))

#Method which scheduler starts 
def start_retrain_thread():
    global sceduled_df
    global allow_list_ip_addresses

    allow_list_ip_addresses = read_ips_from_file() #Reload white list ip addresses

    if sceduled_df.empty:
        print('DataFrame for scheduled train is empty!')
    else:
        mask = (sceduled_df['date'] >= datetime.datetime.now() + datetime.timedelta(hours=-abs(retrain_data_period))) & (sceduled_df['date'] <= datetime.datetime.now())
        sceduled_df = sceduled_df.loc[mask]

        if sceduled_df.shape[0] < packeges_to_learn:
            print(f'Not enought packeges to train. Need minimum {packeges_to_learn} but got {sceduled_df.shape[0]}')

        thread = threading.Thread(target = do_train_job, args=(sceduled_df,))
        thread.start()

class PacketbeatReader(threading.Thread):
    """A thread that reads packetbeat files, processes them, and
    makes them available to consumers.

    - When initialized, will start reading Packetbeat packets on the provided location.
    - When started, will start processing and parsing queued packets.
    - When stopped, will stop processing.
    - When joined, will wait for the listener to exit
    """

    def __init__(self):
        logger.info("Starting the Packetbeta reader")
        self.output = queue.Queue()
        self._shutdown = threading.Event()
        super().__init__()

    def get(self, block=True, timeout=None):
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
        conf = {
            'bootstrap.servers': kafka_ip_address,
            'group.id': 'packetbeat-group',
            'auto.offset.reset': 'earliest'
        }
        consumer = Consumer(conf)
        consumer.subscribe([kafka_topic_name])

        try:
            while not self._shutdown.is_set():
                msg = consumer.poll(timeout=1.0)
                if msg is None:
                    continue
                if msg.error():
                    if msg.error().code() == KafkaError._PARTITION_EOF:
                        continue
                    else:
                        logger.error(msg.error())
                        break
                #print(msg.value())
                raw_flow = json.loads(msg.value().decode('utf-8'))
                src_ip = raw_flow.get("source").get("ip")
                src_port = raw_flow.get("source").get("port")
                dst_ip = raw_flow.get("destination").get("ip")
                dst_port = raw_flow.get("destination").get("port")
                proto = raw_flow.get("network").get("transport")
                in_bytes = raw_flow.get("destination").get("bytes",0)
                out_bytes = raw_flow.get("source").get("bytes", 0)
                in_packets = raw_flow.get("destination").get("packets",0)
                out_packets = raw_flow.get("source").get("packets",0)
                duration = raw_flow.get("event").get("duration")
                host_name = raw_flow.get("host").get("name",'not available')
                
                data = f"{src_ip},{src_port},{dst_ip},{dst_port},{host_name},{proto},{in_bytes},{out_bytes},{in_packets},{out_packets},{duration}"
                
                if "None" not in data:
                    self.output.put(data)
                    consumer.commit(msg)
        finally:
            consumer.close()

    def stop(self):
        #logger.info("Shutting down the NetFlow listener")
        self._shutdown.set()

def start_packetbeat_reading():
    reader = PacketbeatReader()
    predictor = NetFlowPredictProcessor()

    schedule.every(start_retrain_every).hours.do(start_retrain_thread)

    print("Listening Packetbeat packets")

    reader.start()  # start processing packets
    predictor.start()  # start predict process
    try:
        # run scheduler panding
        while True:
            schedule.run_pending()
            inc_data = reader.get()
            predictor.put([inc_data.split(",")])

    finally:
        print("Stopping...")
        reader.stop()
        reader.join()
        predictor.stop()
        predictor.join()
        print("Stopped!")

def run_with_packetbeat():
    global isInitialTrain
    try:
        if isInitialTrain:
            collected_packeges = []
            reader_train = PacketbeatReader()
            collected_packeges = []
            print("Reading NetFlow from source to train")
            reader_train.start()  # start reading packets

            try:
                start = time.time()
                while True:
                    inc_data = reader_train.get()
                    # inc_data="{IPV4_SRC_ADDR},{L4_SRC_PORT},{IPV4_DST_ADDR},{L4_DST_PORT},{PROTOCOL},{IN_BYTES},{OUT_BYTES},{IN_PKTS},{OUT_PKTS},0,{fduration},{fversion}".format(**f.data,fduration=duration,fversion=nf_version)
                    if len(collected_packeges) <= packeges_to_learn:
                        collected_packeges.append(inc_data.split(","))

                    if len(collected_packeges) > packeges_to_learn:
                        end = time.time()
                        print("Time taken to collect packages: {0}".format(end - start))
                        print("Packages to train: {0}".format(len(collected_packeges)))
                        break
            finally:
                print("Stopping collecting and begin training")
                reader_train.stop()
                reader_train.join()

                if len(collected_packeges) > 0:
                    initial_train_predict(collected_packeges)
                    collected_packeges.clear()
                    print("Training Finished!")
                    print("-----------------")
                    print("Begin listening and analysing thread !!")
                    isInitialTrain = False

                    start_packetbeat_reading()
                else:
                    print("Packeges to train are null please restart")

        else:
            start_packetbeat_reading()

    except KeyboardInterrupt:
        print("Received KeyboardInterrupt, passing through")
    pass

if __name__ == "netflow.collector":
    logger.error("The collector is currently meant to be used as a CLI tool only.")
    
if __name__ == "__main__":
    run_with_packetbeat()