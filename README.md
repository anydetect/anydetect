## AnyDetect 👋
Anomaly Detection Script by ML and active response

This project provides a Python script for detecting network anomalies using machine learning. It listens for NetFlow packets, processes them, and uses the IsolationForest algorithm for real-time anomaly detection, initial model training, and scheduled retraining.
![image](https://github.com/user-attachments/assets/80000faa-7a1c-45a2-81d7-115cba9f0a5d)

## Installation
```
git clone https://github.com/anydetect/anydetect.git
cd anydetect

python -m venv venv
source venv/bin/activate

pip install -r requirments.txt
```

## Usage
```
python any_detect.py
```

## any_detect.py description:

NetFlow Packet Collection: The script listens for incoming NetFlow packets on a specified IP address and port (in this case, 127.0.0.1:2055), collects them, and processes the flow data.

Anomaly Detection: The script uses three machine learning models to detect anomalies in the NetFlow data:

Isolation Forest: Used for detecting anomalies in the network traffic.
Local Outlier Factor (LOF): A novelty detection algorithm.
XGBoost: A powerful gradient boosting classifier.
Initial Training: If no pre-trained models are found (IsolationForestModel.pkl, LocalOutlayerModel.pkl, XgbModel.pkl, and Model_scaler.pkl), the script collects a certain number of NetFlow packets (packeges_to_learn = 1,000,000) and trains the models for the first time. Once trained, the models are saved to disk for future use.

Real-Time Prediction: The script processes incoming NetFlow data in real-time, and the trained models are used to predict whether the data contains any anomalies.

Scheduled Retraining: The script can retrain the models at regular intervals (every 2 hours by default) using newly collected data.

Logging: The script logs its progress and outputs useful debugging information using Python's built-in logging library.


## action_script.py description:

The provided Python script is designed to remotely manage a switch port on a FortiGate device based on an IP address by:

Extracting an IP address from a data.json file.
Using SSH to connect to the FortiGate device.
Looking up the MAC address corresponding to the given IP in the ARP table.
Fetching the switch MAC address table to find the corresponding switch and port for that MAC address.
Disabling the port on the FortiGate-managed switch where the MAC address is located.

## netflow_Replyer.ipynb  description:
Purpose: The notebook includes a Python script to replay an nfcapd (NetFlow capture) file using the nfreplay command. It sends the replayed data to a specified IP and port.

Key Functions:

replay_nfcapd_file: This function replays a NetFlow capture file (nfcapd) to a destination IP and port using the nfreplay tool. It captures output and handles errors during the process.
A call to this function is made with the file nfcapd.202409252000 sent to 127.0.0.1 on port 2055

##  Read_dump_file.ipynb description:

Jupyter Notebook that contains code, possibly related to reading and processing NetFlow data or something similar based on your earlier script. Since it's a .ipynb file, it could include Python code cells, text descriptions (Markdown), and output cells.

Here are the likely contents you can expect in a Jupyter notebook:

Code cells: These cells contain Python code or any other supported languages. The code could be for reading a file, processing data, or generating output.
Markdown cells: These cells often contain text instructions, explanations, or comments about the code.
Output cells: If any code cells are executed, their results (such as printed text, graphs, or other outputs) are shown here.


## config.ini description:

Switch credentials 


## Modules

- `logging`: For logging events.
- `queue`: For managing queues.
- `signal`: For handling signals.
- `socket`: For network communication.
- `socketserver`: For creating network servers.
- `threading`: For multi-threading.
- `time`: For time-related functions.
- `collections`: For named tuples.
- `pandas`: For data manipulation and analysis.
- `datetime`: For date and time operations.
- `sklearn`: For machine learning models and preprocessing.
- `xgboost`: For XGBoost model.
- `os`: For interacting with the operating system.
- `pickle`: For serializing and deserializing objects.
- `json`: For JSON operations.
- `schedule`: For scheduling tasks.

## Classes

- `QueuingRequestHandler`: Handles incoming UDP requests and queues them.
- `QueuingUDPListener`: A threaded UDP server that queues incoming requests.
- `ThreadedNetflowCollectProcessor`: Collects data for retraining.
- `ThreadedNetFlowPredictProcessor`: Processes incoming packets and predicts anomalies.
- `ThreadedNetFlowListener`: Listens for incoming NetFlow packets and processes them.

## Functions

- `standartize_process(df)`: Standardizes the input DataFrame.
- `do_train_job(df_data)`: Retrains the models with the given data.
- `initial_train_predict(raw_data)`: Performs initial training of the models.
- `validate(y, result)`: Validates the model predictions.
- `start_retrain_thread()`: Starts a new thread for retraining the models.
- `start_listening()`: Starts the listener and predictor threads for real-time processing.

## Global Variables

- `ip_address`: IP address to listen on.
- `port`: Port to listen on.
- `isInitialTrain`: Flag indicating if initial training is required.
- `packeges_to_learn`: Number of packages to collect for initial training.
- `saveAnomalyPath`: Directory to save detected anomalies.
- `sceduled_df`: DataFrame for scheduled retraining data.
- `retrain_data_period`: Period to get data for retraining in hours.
- `start_retrain_every`: Interval to start retraining in hours.
- `isExist`: Flag indicating if the saveAnomalyPath exists.
- `scaler`: Scaler for data normalization.
- `clf`: Isolation Forest model.
- `lof`: Local Outlier Factor model.
- `xgb_classifier`: XGBoost classifier.
- `PACKET_TIMEOUT`: Timeout for dropping undecodable packets.
- `logger`: Logger for the script.

