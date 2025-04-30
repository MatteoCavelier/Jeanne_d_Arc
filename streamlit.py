import streamlit as st
import pandas as pd
import threading
import time
from scapy.all import sniff
import pickle
from queue import Queue

with open("model_RF.pkl", "rb") as f:
    model_RF = pickle.load(f)

if "alerts" not in st.session_state:
    st.session_state.alerts = []


packet_queue = Queue()

def classifier(model, **kwargs):
    columns = ["duration", "protocol_type", "src_bytes", "dst_bytes", "flag", "count", "srv_count",
               "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate"]
    default_values = [1, 6, 500, 0, 0, 1, 1, 0.5, 0.5, 0.5]
    input_data = {col: kwargs.get(col, default_values[i]) for i, col in enumerate(columns)}
    x = pd.DataFrame([input_data], columns=columns)
    prediction = model.predict(x)
    return prediction[0]

def process_packet(packet):
    try:
        features = {
            "duration": 1,
            "protocol_type": getattr(packet, 'proto', 6),
            "src_bytes": len(packet),
            "dst_bytes": 0,
            "flag": 0,
            "count": 1,
            "srv_count": 1,
            "same_srv_rate": 0.5,
            "diff_srv_rate": 0.5,
            "srv_diff_host_rate": 0.5,
        }
        label = classifier(model_RF, **features)
        alert = {
            "time": time.strftime("%H:%M:%S"),
            "summary": packet.summary(),
            "label": str(label)
        }
        packet_queue.put(alert)
        print(f"🧠 🚨 {label} → {packet.summary()}")
    except Exception as e:
        print("Erreur dans le callback :", e)

def start_sniffing():
    sniff(prn=process_packet, store=False)

if "sniffing_started" not in st.session_state:
    threading.Thread(target=start_sniffing, daemon=True).start()
    st.session_state.sniffing_started = True

while not packet_queue.empty():
    st.session_state.alerts.append(packet_queue.get())

#Interface Streamlit
st.title("🛡️ Jeanne d'Arc - Détection en temps réel")

#Filtrage
filter_option = st.selectbox("Filtrer les paquets :", ["Tous", "attaque", "normal"])

#Affichage
filtered_alerts = [
    alert for alert in st.session_state.alerts
    if filter_option == "Tous" or alert["label"] == filter_option
]

st.write(f"Nombre de paquets affichés : {len(filtered_alerts)}")
st.dataframe(pd.DataFrame(filtered_alerts))