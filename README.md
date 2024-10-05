## AnyDetect 👋
NetFlow Anomaly Detection Script by ML

This project provides a Python-based script that listens for NetFlow packets, processes them, and detects anomalies using machine learning models. It supports initial model training, real-time anomaly detection, and scheduled retraining of the model. The system is built using scikit-learn for anomaly detection and leverages the IsolationForest algorithm for detecting anomalous network traffic patterns. This script listens for NetFlow packets, processes them, and detects anomalies using machine learning models. It supports initial training, real-time prediction, and scheduled retraining of models.

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



any_detect.py description:

~~~
NetFlow Packet Collection: The script listens for incoming NetFlow packets on a specified IP address and port (in this case, 127.0.0.1:2055), collects them, and processes the flow data.

Anomaly Detection: The script uses three machine learning models to detect anomalies in the NetFlow data:

Isolation Forest: Used for detecting anomalies in the network traffic.
Local Outlier Factor (LOF): A novelty detection algorithm.
XGBoost: A powerful gradient boosting classifier.
Initial Training: If no pre-trained models are found (IsolationForestModel.pkl, LocalOutlayerModel.pkl, XgbModel.pkl, and Model_scaler.pkl), the script collects a certain number of NetFlow packets (packeges_to_learn = 1,000,000) and trains the models for the first time. Once trained, the models are saved to disk for future use.

Real-Time Prediction: The script processes incoming NetFlow data in real-time, and the trained models are used to predict whether the data contains any anomalies.

Scheduled Retraining: The script can retrain the models at regular intervals (every 2 hours by default) using newly collected data.

Logging: The script logs its progress and outputs useful debugging information using Python's built-in logging library.
~~~


response1.py Description:

~~~
The provided Python script is designed to remotely manage a switch port on a FortiGate device based on an IP address by:

Extracting an IP address from a data.json file.
Using SSH to connect to the FortiGate device.
Looking up the MAC address corresponding to the given IP in the ARP table.
Fetching the switch MAC address table to find the corresponding switch and port for that MAC address.
Disabling the port on the FortiGate-managed switch where the MAC address is located.
~~~

