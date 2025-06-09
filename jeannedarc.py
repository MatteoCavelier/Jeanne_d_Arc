import streamlit as interface
from scapy.all import sniff, send
from scapy.layers.inet import IP, TCP
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.metrics import classification_report
import threading
import random
import matplotlib.pyplot as plt
import os
import joblib
from collections import defaultdict, deque
import time


global_ip_cible = "192.168.1.194"
global_ip_retour = "192.168.1.20"
alerts_not_in_interface = []


# ====================================================================================================================== Session state
# Pour initialiser l'interface des alertes
# Session_state c'est une genre de sauvegarde
if 'alerts' not in interface.session_state:
    interface.session_state.alerts = []
if 'ia_in_action' not in interface.session_state:
    interface.session_state.ia_in_action = False

# ====================================================================================================================== Charger et entraîner modèle
@interface.cache_resource
def load_model():
    if os.path.exists("mon_model_rf.joblib"):
        model_prep = joblib.load("mon_model_rf.joblib")
    else:
        dataset = pd.read_csv("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
        dataset.columns = dataset.columns.str.strip()
        keep_cols = [
            "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Label"
        ]
        dataset = dataset[keep_cols].dropna().drop_duplicates()
        dataset = dataset[dataset['Label'].isin(['BENIGN', 'DoS Hulk', 'DDoS'])]
        dataset['Label'] = dataset['Label'].apply(lambda x: 'attack' if x != 'BENIGN' else 'normal')

        data_content = dataset.drop(columns='Label')
        data_label = dataset['Label']

        X_train_prep, X_test_prep, y_train, y_test = train_test_split(
            data_content, data_label, test_size=0.2, stratify=data_label, random_state=42
        )

        param = {
            'n_estimators': [50, 100, 150],
            'max_depth': [5, 10, 20, None],
            'min_samples_split': [2, 5, 10],
            'min_samples_leaf': [1, 2, 4],
            'bootstrap': [True, False]
        }

        model_brut = RandomForestClassifier(random_state=42)
        search = RandomizedSearchCV(model_brut, param_distributions=param, n_iter=10, cv=3,
                                    scoring='accuracy', n_jobs=-1, random_state=42)
        search.fit(X_train_prep, y_train)
        model_prep = search.best_estimator_

        # Sauvegarde du modèle
        joblib.dump(model_prep, "mon_model_rf.joblib")

        y_pred = model_prep.predict(X_test_prep)
        report = classification_report(y_test, y_pred, output_dict=True)

        with interface.sidebar.expander("Évaluation du modèle optimisé", expanded=False):
            interface.write("### Rapport de classification")
            report_attack = report['attack']
            interface.write(f"Précision : {report_attack['precision']:.4f}")

        return model_prep, data_content.columns.tolist(), data_content, data_label, dataset

    dataset = pd.read_csv("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
    dataset.columns = dataset.columns.str.strip()
    dataset = dataset[[
        "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Label"
    ]].dropna().drop_duplicates()
    dataset = dataset[dataset['Label'].isin(['BENIGN', 'DoS Hulk', 'DDoS'])]
    dataset['Label'] = dataset['Label'].apply(lambda x: 'attack' if x != 'BENIGN' else 'normal')
    data_content = dataset.drop(columns='Label')
    data_label = dataset['Label']

    return model_prep, data_content.columns.tolist(), data_content, data_label, dataset



model, categories_dataset, global_data_content, global_data_label, global_dataset = load_model()

# ====================================================================================================================== Graphiques dans la sidebar
with interface.sidebar.expander("Répartition des ATK/NRML", expanded=False):
    nombre_de_atk_nrml = global_data_label.value_counts()
    figure_repartition, axe_repartition = plt.subplots()
    axe_repartition.pie(nombre_de_atk_nrml, labels=nombre_de_atk_nrml.index, autopct='%1.1f%%', startangle=90)
    axe_repartition.axis('equal')
    interface.pyplot(figure_repartition)

with interface.sidebar.expander("Importance des variables", expanded=False):
    param_important = model.feature_importances_
    serie_panda = pd.Series(param_important, index=global_data_content.columns).sort_values(ascending=True)
    figure_fi, axe_fi = plt.subplots()
    serie_panda.plot(kind='barh', ax=axe_fi)
    axe_fi.set_title("Importance des variables")
    interface.pyplot(figure_fi)

# ====================================================================================================================== Prédiction
def do_prediction(param_model, data_to_predict):
    try:
        one_line_data_frame = pd.DataFrame([data_to_predict], columns=categories_dataset)
        return param_model.predict(one_line_data_frame)[0]
    except Exception as error:
        interface.session_state.alerts.append(f"Erreur prediction : {error}")
        return None



# ====================================================================================================================== Suivi des connexions

TIMEOUT_INACTIVITY = 10  # secondes

conn_flows = {}

source_ip_tracker = defaultdict(lambda: deque())


def make_flow_key(ip1, port1, ip2, port2):
    if (ip1, port1) < (ip2, port2):
        return (ip1, port1, ip2, port2)
    else:
        return (ip2, port2, ip1, port1)

def process_and_reset_conn(flow_key):
    conn = conn_flows.get(flow_key)
    if not conn or not conn["packets"]:
        return

    total_fwd_packets = 0
    total_bwd_packets = 0
    total_len_fwd = 0
    total_len_bwd = 0

    src = conn["src_ip"]
    sport = conn["src_port"]
    dst = conn["dst_ip"]
    dport = conn["dst_port"]

    for pkt in conn["packets"]:
        if IP in pkt and TCP in pkt:
            ip = pkt[IP]
            tcp = pkt[TCP]
            pkt_tuple = (ip.src, tcp.sport, ip.dst, tcp.dport)
            if pkt_tuple == (src, sport, dst, dport):
                total_fwd_packets += 1
                total_len_fwd += len(pkt)
            elif pkt_tuple == (dst, dport, src, sport):
                total_bwd_packets += 1
                total_len_bwd += len(pkt)
            else:
                print(f"[WARN] Paquet hors flux attendu : {pkt_tuple}")

    flow_duration = int((conn["end"] - conn["start"]) * 1e6)  # microsecondes

    sample = {
        'Flow Duration': flow_duration,
        'Total Fwd Packets': total_fwd_packets,
        'Total Backward Packets': total_bwd_packets,
        'Total Length of Fwd Packets': total_len_fwd,
        'Total Length of Bwd Packets': total_len_bwd
    }

    result_prediction = do_prediction(model, sample)
    print(f"[RESULT] Prédiction flux {src}:{sport} <-> {dst}:{dport} : {result_prediction}")

    if result_prediction == "attack":
        alerts_not_in_interface.append(f"[IA] Attaque détectée de {src}:{sport} vers {dst}:{dport}")
        print(f"[ALERTE] Attaque détectée de {src}:{sport} vers {dst}:{dport}")


def handle_packet(packet):
    try:
        if IP in packet and TCP in packet:
            ip_layer = packet[IP]
            tcp_layer = packet[TCP]

            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport

            if dst_ip.startswith("224.") or dst_ip.startswith("239."):
                return

            now = packet.time

            flow_key = make_flow_key(src_ip, src_port, dst_ip, dst_port)

            if flow_key not in conn_flows:
                conn_flows[flow_key] = {
                    "packets": [],
                    "start": now,
                    "end": now,
                    "last_seen": now,
                    "src_ip": src_ip,
                    "src_port": src_port,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port
                }

            conn = conn_flows[flow_key]

            pkt_tuple = (src_ip, src_port, dst_ip, dst_port)
            forward_tuple = (conn["src_ip"], conn["src_port"], conn["dst_ip"], conn["dst_port"])
            backward_tuple = (conn["dst_ip"], conn["dst_port"], conn["src_ip"], conn["src_port"])

            if pkt_tuple == forward_tuple or pkt_tuple == backward_tuple:
                conn["packets"].append(packet)
                conn["end"] = now
                conn["last_seen"] = now

                FIN_FLAG = 0x01
                RST_FLAG = 0x04
                tcp_flags = tcp_layer.flags

                if tcp_flags & FIN_FLAG or tcp_flags & RST_FLAG:
                    process_and_reset_conn(flow_key)

            else:
                print(f"[WARN] Paquet hors flux pour clé {flow_key}")

            to_remove = []
            for key, c in conn_flows.items():
                if now - c["last_seen"] > TIMEOUT_INACTIVITY:
                    process_and_reset_conn(key)
                    to_remove.append(key)

            for key in to_remove:
                if key in conn_flows:
                    del conn_flows[key]

    except Exception as e:
        alerts_not_in_interface.append(f"Erreur dans handle_packet : {e}")
        print(f"[ERREUR] handle_packet : {e}")
    # [NEW] Agrégation des flux par IP source pour détection manuelle
    src_ip = ip_layer.src
    now_time = time.time()
    source_ip_tracker[src_ip].append(now_time)

    # Supprime les timestamps plus vieux que 10 secondes
    while source_ip_tracker[src_ip] and now_time - source_ip_tracker[src_ip][0] > 10:
        source_ip_tracker[src_ip].popleft()

    # Règle manuelle simple
    if len(source_ip_tracker[src_ip]) > 1000:
        alert_msg = f"[MANUEL] Comportement suspect : {len(source_ip_tracker[src_ip])} flux de {src_ip} en moins de 10s"
        print(alert_msg)
        alerts_not_in_interface.append(alert_msg)


def read_network():
    # IP c'est pour accepter tout les type de protocole
    sniff(filter="ip", prn=handle_packet, store=False)


# ====================================================================================================================== Fausse attaque

# Exemple de data donner :
# {'Flow Duration': 1293792, 'Total Fwd Packets': 3, 'Total Backward Packets': 7, 'Total Length of Fwd Packets': 26, 'Total Length of Bwd Packets': 11607}
def get_fake_attack():
    # Les deux lignes du dessous prenne une ligne du dataset ex: celle au dessus de la fonction
    # sample = global_dataset[global_dataset['Label'] == 'attack'].dropna()
    # process_sample = sample.iloc[0][categories_dataset].to_dict()
    process_sample = {'Flow Duration': 1293666, 'Total Fwd Packets': 4, 'Total Backward Packets': 8, 'Total Length of Fwd Packets': 22,
                      'Total Length of Bwd Packets': 10000}
    process_sample = {'Flow Duration': 53340, 'Total Fwd Packets': 10, 'Total Backward Packets': 0, 'Total Length of Fwd Packets': 22,
                      'Total Length of Bwd Packets': 10000}
    return process_sample


# L'attaque en temps reel dans le réseaux pour que l'ia la recoive
# C'est une SYN flood donc envoie de plein de requete en peu de temps
def real_time_attack(ip_1, ip_2, port, count=500):
    for _ in range(count):
        # Envoie d'une requête SYN
        packet = IP(dst=ip_1) / TCP(dport=port, flags="S", seq=random.randint(1, 10000))
        send(packet, verbose=0)

        # Simulation de réponse SYN-ACK (pour enrichir les features)
        #fake_response = IP(src=ip_1, dst=ip_2) / TCP(sport=port, dport=random.randint(1024, 65535), flags="SA", seq=random.randint(1, 10000))
        #send(fake_response, verbose=0)



# ====================================================================================================================== Interface
interface.title("Jeanne D'Arc")

if interface.button("Lancer la surveillance") and not interface.session_state.ia_in_action:
    interface.session_state.ia_in_action = True
    threading.Thread(target=read_network, daemon=True).start()
    interface.write("Surveillance lancée")

if interface.button("Donner attaque à l'IA (test du modèle)"):
    data = get_fake_attack()
    result = do_prediction(model, data)
    if result == "attack":
        alerts_not_in_interface.append("Détection OK sur attaque simulée.")
    else:
        alerts_not_in_interface.append("Détection raté sur attaque simulée.")

if interface.button("Envoyer attaque sur réseaux (Linux uniquement)"):
    real_time_attack(global_ip_cible, global_ip_retour, 80, count=1000)

# Le trait graphique de séparation
interface.divider()

# Affiche les alertes
with interface.expander("Alertes", expanded=True):
    if alerts_not_in_interface:
        interface.session_state.alerts += alerts_not_in_interface
        # Affiche les 10 derniere attaque en commencementpar la derniere
        for alert in reversed(interface.session_state.alerts[-10:]):
            interface.write(alert)
        alerts_not_in_interface.clear()

