import streamlit as interface
from scapy.all import sniff, send
from scapy.layers.inet import IP, TCP
import pandas as pandas_lib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.metrics import classification_report
import threading
import random
import matplotlib.pyplot as plt
import os
import joblib


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
        dataset = pandas_lib.read_csv("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
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

        # Save le modele
        joblib.dump(model_prep, "mon_model_rf.joblib")

        y_pred = model_prep.predict(X_test_prep)
        report = classification_report(y_test, y_pred, output_dict=True)

        with interface.sidebar.expander("Évaluation du modèle optimisé", expanded=False):
            interface.write("### Rapport de classification")
            report_attack = report['attack']
            interface.write(f"Précision : {report_attack['precision']:.4f}")

    dataset = pandas_lib.read_csv("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
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
    serie_panda = pandas_lib.Series(param_important, index=global_data_content.columns).sort_values(ascending=True)
    figure_fi, axe_fi = plt.subplots()
    serie_panda.plot(kind='barh', ax=axe_fi)
    axe_fi.set_title("Importance des variables")
    interface.pyplot(figure_fi)

# ====================================================================================================================== Prédiction
def do_prediction(param_model, data_to_predict):
    try:
        one_line_data_frame = pandas_lib.DataFrame([data_to_predict], columns=categories_dataset)
        return param_model.predict(one_line_data_frame)[0]
    except Exception as error:
        interface.session_state.alerts.append(f"Erreur prediction : {error}")
        return None



# ====================================================================================================================== Suivi des connexions

conn = {
    "packets": [],
    "start": None,
    "end": None,
    "src": None,
    "dst": None
}

def handle_packet(packet):
    try:
        if IP in packet and TCP in packet:
            src = packet[IP].src
            dst = packet[IP].dst

            # Ignore les paquets multicast
            if dst.startswith("224.") or dst.startswith("239."):
                return

            now = packet.time

            # Initialisation du flux si nécessaire
            if conn["start"] is None:
                conn["start"] = now
                conn["src"] = src
                conn["dst"] = dst
                conn["packets"] = []

            conn["end"] = now
            conn["packets"].append(packet)

            print(f"[INFO] Nouveau paquet ajouté : {src} -> {dst} | Total : {len(conn['packets'])}")

            # Analyse du flux si durée > 2 sec ou >= 20 paquets
            if now - conn["start"] > 2 or len(conn["packets"]) >= 20:
                print("[INFO] Conditions de traitement du flux atteintes")

                total_fwd_packets = 0
                total_bwd_packets = 0
                total_len_fwd = 0
                total_len_bwd = 0

                for pkt in conn["packets"]:
                    if IP in pkt and TCP in pkt:
                        ip = pkt[IP]
                        if ip.src == conn["src"] and ip.dst == conn["dst"]:
                            total_fwd_packets += 1
                            total_len_fwd += len(pkt)
                        elif ip.src == conn["dst"] and ip.dst == conn["src"]:
                            total_bwd_packets += 1
                            total_len_bwd += len(pkt)
                        else:
                            print(f"[WARN] Paquet hors du flux attendu : {ip.src} -> {ip.dst}")

                flow_duration = int((conn["end"] - conn["start"]) * 1e6)  # microsecondes

                sample = {
                    'Flow Duration': flow_duration,
                    'Total Fwd Packets': total_fwd_packets,
                    'Total Backward Packets': total_bwd_packets,
                    'Total Length of Fwd Packets': total_len_fwd,
                    'Total Length of Bwd Packets': total_len_bwd
                }

                print(f"[DEBUG] Échantillon extrait : {sample}")

                result_prediction = do_prediction(model, sample)
                print(f"[RESULT] Prédiction : {result_prediction}")

                if sample['Total Fwd Packets'] > 500: result_prediction = "attack"

                if result_prediction == "attack":
                    alerts_not_in_interface.append(f"[IA] Attaque détectée de {src} vers {dst}")
                    print(f"[ALERTE] Attaque détectée de {src} vers {dst}")

                # Réinitialisation du flux
                conn["start"] = None
                conn["end"] = None
                conn["packets"] = []
                conn["src"] = None
                conn["dst"] = None

    except Exception as e:
        alerts_not_in_interface.append(f"Erreur dans handle_packet : {e}")
        print(f"[ERREUR] handle_packet : {e}")



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

if interface.button("Envoyer attaque sur réseaux"):
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

