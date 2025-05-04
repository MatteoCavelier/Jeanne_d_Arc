import streamlit as st
from scapy.all import sniff, send
from scapy.layers.inet import IP, TCP
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.metrics import classification_report
import threading
import time
from collections import defaultdict
import random
import matplotlib.pyplot as plt

# ====================================================================================================================== Session state
# Pour initialiser l'interface des alertes
if 'alerts' not in st.session_state:
    st.session_state.alerts = []
if 'monitor_started' not in st.session_state:
    st.session_state.monitor_started = False


# ====================================================================================================================== Charger et entraîner modèle
@st.cache_resource
def load_model():
    df = pd.read_csv("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
    df.columns = df.columns.str.strip()

    # Colonnes qu'on garde
    cols = [
        "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Label"
    ]
    df = df[cols].dropna().drop_duplicates()

    df = df[df['Label'].isin(['BENIGN', 'DoS Hulk', 'DDoS'])]
    df['Label'] = df['Label'].apply(lambda x: 'attack' if x != 'BENIGN' else 'normal')

    X = df.drop(columns='Label')
    y = df['Label']

    # Séparation en train et test
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, stratify=y, random_state=42)

    # Hyperparamètres à tester
    param_dist = {
        'n_estimators': [50, 100, 150],
        'max_depth': [5, 10, 20, None],
        'min_samples_split': [2, 5, 10],
        'min_samples_leaf': [1, 2, 4],
        'bootstrap': [True, False]
    }

    rf = RandomForestClassifier(random_state=42)
    search = RandomizedSearchCV(rf, param_distributions=param_dist, n_iter=10, cv=3, scoring='accuracy', n_jobs=-1, random_state=42)
    search.fit(X_train, y_train)
    best_clf = search.best_estimator_

    # Évaluation du modèle optimisé
    y_pred = best_clf.predict(X_test)
    report = classification_report(y_test, y_pred, output_dict=True)

    # Affichage dans Streamlit des tests
    with st.sidebar.expander("📈 Évaluation du modèle optimisé"):
        st.write("### Rapport de classification")
        report_attack = report['attack']
        st.write(f"Précision : {report_attack['precision']:.4f}")

    return best_clf, X.columns.tolist(), X, y, df


model, features, X, y, df = load_model()

# ====================================================================================================================== Graphiques dans la sidebar
with st.sidebar.expander("Répartition des ATK/NRML"):
    class_counts = y.value_counts()
    fig1, ax1 = plt.subplots()
    ax1.pie(class_counts, labels=class_counts.index, autopct='%1.1f%%', startangle=90)
    ax1.axis('equal')
    st.pyplot(fig1)

with st.sidebar.expander("Importance des variables"):
    importances = model.feature_importances_
    feat_imp = pd.Series(importances, index=X.columns).sort_values(ascending=True)
    fig3, ax3 = plt.subplots()
    feat_imp.plot(kind='barh', ax=ax3)
    ax3.set_title("Importance des variables")
    st.pyplot(fig3)


# ====================================================================================================================== Prédiction
def do_prediction(clf, data):
    try:
        df = pd.DataFrame([data], columns=features)
        return clf.predict(df)[0]
    except Exception as e:
        st.session_state.alerts.append(f"Erreur prédiction : {e}")
        return None


# ====================================================================================================================== Suivi des connexions
connections = defaultdict(lambda: {
    "start": None, "fwd_pkt": 0, "bwd_pkt": 0, "fwd_bytes": 0, "bwd_bytes": 0
})
alerts_tmp = []


def handle_packet(pkt):
    try:
        if IP in pkt:
            src, dst = pkt[IP].src, pkt[IP].dst
            if dst.startswith("224.") or dst.startswith("239."):
                return

            key = (src, dst)
            conn = connections[key]
            if conn["start"] is None:
                conn["start"] = time.time()

            size = len(pkt)
            if pkt[IP].src == src:
                conn["fwd_pkt"] += 1
                conn["fwd_bytes"] += size
            else:
                conn["bwd_pkt"] += 1
                conn["bwd_bytes"] += size

            dur = (time.time() - conn["start"]) * 1_000_000  # microsec

            if dur < 1000 or (conn["fwd_pkt"] + conn["bwd_pkt"]) < 5:
                return

            sample = {
                "Flow Duration": dur,
                "Total Fwd Packets": conn["fwd_pkt"],
                "Total Backward Packets": conn["bwd_pkt"],
                "Total Length of Fwd Packets": conn["fwd_bytes"],
                "Total Length of Bwd Packets": conn["bwd_bytes"]
            }

            result = do_prediction(model, sample)
            if result == "attack":
                alerts_tmp.append(f"⚠️ Attaque détectée de {src} vers {dst}")
    except Exception as e:
        alerts_tmp.append(f"Erreur dans handle_packet : {e}")


def start_capture():
    sniff(iface=r"\Device\NPF_{DB64A3AD-B8A6-4E27-9233-8BB72C8AF18A}", filter="ip", prn=handle_packet, store=False)


# ====================================================================================================================== Fausse attaque
def get_fake_attack():
    sample = df[df['Label'] == 'attack'].dropna()
    return sample.iloc[0][features].to_dict()


def send_syn_flood(ip, port, count=500):
    for _ in range(count):
        pkt = IP(dst=ip) / TCP(dport=port, flags="S", seq=random.randint(1, 10000))
        send(pkt, verbose=0)


# ====================================================================================================================== Interface
st.title("Détection d'attaques réseau")

if st.button("Lancer la surveillance") and not st.session_state.monitor_started:
    st.session_state.monitor_started = True
    threading.Thread(target=start_capture, daemon=True).start()
    st.write("Surveillance lancée")

if st.button("Simuler une attaque (test modèle)"):
    data = get_fake_attack()
    result = do_prediction(model, data)
    if result == "attack":
        alerts_tmp.append("Détection OK sur attaque simulée.")
    else:
        alerts_tmp.append("Détection raté sur attaque simulée.")

if st.button("Envoyer manuel ATK"):
    send_syn_flood("192.168.1.194", 80)

st.divider()

with st.expander("Alertes", expanded=True):
    if alerts_tmp:
        st.session_state.alerts += alerts_tmp
        alerts_tmp.clear()
    for alert in reversed(st.session_state.alerts[-10:]):
        st.write(alert)
