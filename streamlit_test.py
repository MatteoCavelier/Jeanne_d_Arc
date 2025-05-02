import streamlit as st
from scapy.all import sniff, send
from scapy.layers.inet import IP, TCP, UDP
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from collections import defaultdict, deque
import threading
import time
from sklearn.preprocessing import LabelEncoder
import requests

# ===================== Initialize session state =====================
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'monitor_started' not in st.session_state:
    st.session_state.monitor_started = False

# ===================== Chargement et entraînement du modèle =====================
@st.cache_resource
def train_model():
    url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
    columns = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
               "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
               "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count", "srv_count",
               "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
               "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
               "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
               "label"]

    dataset = pd.read_csv(url, names=columns)

    relevant_columns = ["duration", "protocol_type", "src_bytes", "dst_bytes", "flag", "count", "srv_count", "same_srv_rate", "diff_srv_rate",
                        "srv_diff_host_rate", "label"]
    dataset = dataset[relevant_columns]
    dataset['label'] = dataset['label'].apply(lambda x: 'normal' if 'normal' in str(x) else 'attack')

    dataset.dropna(inplace=True)
    dataset.drop_duplicates(inplace=True)

    if dataset['duration'].dtype == 'object':
        dataset['duration'] = pd.to_numeric(dataset['duration'], errors='coerce')

    categorical_cols = ["protocol_type", "flag"]
    for col in categorical_cols:
        dataset[col] = pd.factorize(dataset[col])[0]

    X = dataset.drop(columns=["label"], axis=1)
    Y = dataset["label"]
    model = RandomForestClassifier(n_estimators=100)
    model.fit(X, Y)
    return model, X.columns, X.mean().to_dict()


model_RF, feature_names, default_values = train_model()

# ===================== Fonctions prédiction =====================
def predict(model, features):
    features_df = pd.DataFrame([features], columns=feature_names)

    # Afficher les types et les valeurs de features pour déboguer
    st.write("Features envoyées au modèle :")
    st.write(features_df)

    try:
        prediction = model.predict(features_df)[0]
    except Exception as e:
        st.session_state.alerts.append(f"⚠️ Erreur dans la prédiction: {str(e)}")
        return None

    return prediction


# ===================== Sniffer (thread séparé) =====================
WINDOW_SIZE = 100
TIME_WINDOW = 60
connection_data = defaultdict(lambda: {"src_bytes": 0})
dst_services = defaultdict(set)
dst_connection_count = defaultdict(int)
recent_connections = defaultdict(lambda: deque(maxlen=WINDOW_SIZE))
recent_counts = defaultdict(lambda: deque())
service_connections = defaultdict(set)
connection_start_time = {}

alert_buffer = []  # Tampon pour stocker les alertes

def process_packet(packet):
    try:
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto = packet[IP].proto
            conn_key = (src_ip, dst_ip)
            dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else 0)
            current_time = time.time()

            if conn_key not in connection_start_time:
                connection_start_time[conn_key] = current_time

            duration = current_time - connection_start_time[conn_key]

            protocol_map = {6: 0, 17: 1}
            flag_map = {"S": 1, "A": 2, "F": 3, "R": 4, "P": 5, "U": 6}

            connection_data[conn_key]["src_bytes"] += len(packet)
            dst_bytes = connection_data[(dst_ip, src_ip)]["src_bytes"]

            dst_services[dst_ip].add(dst_port)
            dst_connection_count[dst_ip] += 1
            total_dst_connections = dst_connection_count[dst_ip]
            different_services = len(dst_services[dst_ip])
            diff_srv_rate = (different_services - 1) / total_dst_connections if total_dst_connections > 1 else 0

            recent_connections[src_ip].append(dst_port)
            same_srv_count = sum(1 for port in recent_connections[src_ip] if port == dst_port)
            total_recent = len(recent_connections[src_ip])
            same_srv_rate = same_srv_count / total_recent if total_recent > 0 else 0

            recent_counts[src_ip].append((dst_ip, current_time))
            recent_counts[src_ip] = deque([(d, t) for d, t in recent_counts[src_ip] if current_time - t <= TIME_WINDOW])
            count = sum(1 for d, t in recent_counts[src_ip] if d == dst_ip)

            service_key = (src_ip, dst_port)
            service_connections[service_key].add(dst_ip)
            total_srv_connections = len(service_connections[service_key])
            srv_diff_host_rate = (total_srv_connections - 1) / total_srv_connections if total_srv_connections > 1 else 0

            features = {
                "duration": duration,
                "protocol_type": protocol_map.get(proto, 2),
                "src_bytes": connection_data[conn_key]["src_bytes"],
                "dst_bytes": dst_bytes,
                "flag": flag_map.get(packet[TCP].flags, 0) if TCP in packet else 0,
                "count": count,
                "srv_count": 1,
                "same_srv_rate": same_srv_rate,
                "diff_srv_rate": diff_srv_rate,
                "srv_diff_host_rate": srv_diff_host_rate,
            }

            # Appeler la fonction de prédiction avec débogage
            prediction = predict(model_RF, features)
            if prediction == "attack":
                alert_buffer.append(f"🚨 ATTACK from {src_ip}:{dst_port} to {dst_ip}")
    except Exception as e:
        alert_buffer.append(f"⚠️ Erreur: {str(e)}")


def start_sniffing():
    sniff(filter="ip", timeout=5, prn=process_packet, store=False)

# ===================== Interface Streamlit =====================

st.title("🛡️ Jeanne d'Arc - Détection d'attaques réseau")

if st.button("🚀 Lancer la surveillance réseau") and not st.session_state.monitor_started:
    st.session_state.monitor_started = True
    threading.Thread(target=start_sniffing, daemon=True).start()
    st.success("Surveillance et génération de trames simulées en cours...")

# Zone dynamique d'affichage
alert_area = st.empty()

# Boucle d'affichage continue des alertes
while True:
    if alert_buffer:
        st.session_state.alerts.extend(alert_buffer)
        alert_buffer.clear()

    with alert_area.container():
        with st.expander("🔔 Voir les 10 dernières alertes", expanded=True):
            for alert in st.session_state.alerts[-10:][::-1]:
                if "normale" in alert:
                    st.success(alert)
                else:
                    st.error(alert)

    time.sleep(1)