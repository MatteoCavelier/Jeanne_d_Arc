import streamlit as st
from scapy.all import sniff, send
from scapy.layers.inet import IP, TCP
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, RandomizedSearchCV
from sklearn.metrics import classification_report
import matplotlib.pyplot as plt
import os
import joblib
from datetime import datetime
import subprocess
import time
import signal
import threading
import queue
from typing import Dict, List
import logging

# Configuration
GLOBAL_IP_CIBLE = "192.168.1.194"
GLOBAL_IP_RETOUR = "192.168.1.20"

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('network_analysis.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class GestionNetwork:
    """Classe pour gérer l'analyse réseau en thread séparé"""

    def __init__(self, model, feature_columns: List[str], alert_queue: queue.Queue):
        self.model = model
        self.feature_columns = feature_columns
        self.alert_queue = alert_queue
        self.is_running = False
        self.thread = None

        # Connexion tracking
        self.conn = {
            "packets": [],
            "start": None,
            "end": None,
            "src": None,
            "dst": None
        }

    def start_analyse(self):
        """Démarre la surveillance réseau dans un thread séparé"""
        if not self.is_running:
            self.is_running = True
            self.thread = threading.Thread(target=self.analyse, daemon=True)
            self.thread.start()
            logger.info("Surveillance réseau démarrée")

    def stop_analyse(self):
        """Arrête la surveillance réseau"""
        self.is_running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2)
        logger.info("Surveillance réseau arrêtée")

    def analyse(self):
        """Fonction principale de surveillance (thread séparé)"""
        while self.is_running:
            try:
                sniff(
                    filter="ip",
                    prn=self.handle_packet,
                    store=False,
                    count=50,
                    timeout=2
                )
            except Exception as e:
                logger.error(f"Erreur dans la surveillance réseau: {e}")
                self.add_alert(f"Erreur surveillance: {e}", "error")

    def handle_packet(self, packet):
        """Traite chaque paquet capturé"""
        try:
            if not (IP in packet and TCP in packet):
                return

            src = packet[IP].src
            dst = packet[IP].dst

            # Ignore les paquets multicast
            if dst.startswith(("224.", "239.")):
                return

            now = packet.time

            # Initialisation du flux
            if self.conn["start"] is None:
                self.conn["start"] = now
                self.conn["src"] = src
                self.conn["dst"] = dst
                self.conn["packets"] = []

            self.conn["end"] = now
            self.conn["packets"].append(packet)

            # Analyse si conditions remplies
            if self.check_analyse(now):
                self.analyse_packet()
                self._reset_connection()

        except Exception as e:
            logger.error(f"Erreur traitement paquet: {e}")
            self.add_alert(f"Erreur paquet: {e}", "error")

    def check_analyse(self, current_time) -> bool:
        """Détermine si le flux doit être analysé"""
        duration = current_time - self.conn["start"]
        packet_count = len(self.conn["packets"])
        return duration > 2 or packet_count >= 100

    def analyse_packet(self):
        """Analyse le flux de paquets et fait une prédiction"""
        try:
            # Calcul des features
            features = self.extract_packet()

            # Prédiction
            prediction = self.prediction(features)

            # Force attack si trop de paquets forward
            if features['Total Fwd Packets'] >= 50:
                prediction = "attack"

            if prediction == "attack":
                self.add_alert(
                    f"Attaque détectée: {self.conn['src']} → {self.conn['dst']}",
                    "attack"
                )

        except Exception as e:
            logger.error(f"Erreur analyse flux: {e}")
            self.add_alert(f"Erreur analyse: {e}", "error")

    def extract_packet(self) -> Dict:
        """Extrait les features du flux de paquets"""
        total_fwd_packets = 0
        total_bwd_packets = 0
        total_len_fwd = 0
        total_len_bwd = 0

        for packet in self.conn["packets"]:
            if IP in packet and TCP in packet:
                ip = packet[IP]
                if ip.src == self.conn["src"] and ip.dst == self.conn["dst"]:
                    total_fwd_packets += 1
                    total_len_fwd += len(packet)
                elif ip.src == self.conn["dst"] and ip.dst == self.conn["src"]:
                    total_bwd_packets += 1
                    total_len_bwd += len(packet)

        flow_duration = int((self.conn["end"] - self.conn["start"]) * 1e6)

        return {
            'Flow Duration': flow_duration,
            'Total Fwd Packets': total_fwd_packets,
            'Total Backward Packets': total_bwd_packets,
            'Total Length of Fwd Packets': total_len_fwd,
            'Total Length of Bwd Packets': total_len_bwd
        }

    def prediction(self, features: Dict) -> str:
        """Fait une prédiction d'attaque"""
        try:
            df = pd.DataFrame([features], columns=self.feature_columns)
            return self.model.predict(df)[0]
        except Exception as e:
            logger.error(f"Erreur prédiction: {e}")
            return "error"

    def add_alert(self, message: str, alert_type: str = "info"):
        """Ajoute une alerte à la queue thread-safe"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        alert = {
            'message': message,
            'type': alert_type,
            'timestamp': timestamp
        }

        try:
            self.alert_queue.put_nowait(alert)

            # Log dans fichier
            log_msg = f"[{alert_type.upper()}] {message} | [{timestamp}]"
            with open("alerts.log", "a") as f:
                f.write(log_msg + "\n")

        except queue.Full:
            logger.warning("Queue d'alertes pleine")

    def _reset_connection(self):
        """Remet à zéro les données de connexion"""
        self.conn = {
            "packets": [],
            "start": None,
            "end": None,
            "src": None,
            "dst": None
        }


class AttackSimulator:
    """Classe pour simuler des attaques"""

    @staticmethod
    def get_fake_attack_data() -> Dict:
        process_sample = {'Flow Duration': 53340, 'Total Fwd Packets': 10, 'Total Backward Packets': 0, 'Total Length of Fwd Packets': 22,
                      'Total Length of Bwd Packets': 10000}
        return process_sample

    @staticmethod
    def launch_syn_flood(target_ip: str, duration: int = 3):
        """Lance une attaque SYN flood réelle"""
        try:
            process = subprocess.Popen(
                ['sudo', 'hping3', '-S', '-p', '80', target_ip, '--flood'],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )

            time.sleep(duration)

            # Arrêt propre
            os.killpg(os.getpgid(process.pid), signal.SIGINT)

            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(os.getpgid(process.pid), signal.SIGKILL)

            logger.info(f"Attaque SYN flood terminée après {duration}s")

        except Exception as e:
            logger.error(f"Erreur attaque SYN flood: {e}")
            raise


@st.cache_resource
def load_model():
    """Charge ou entraîne le modèle ML"""
    model_path = "mon_model_rf.joblib"

    if os.path.exists(model_path):
        model = joblib.load(model_path)
        logger.info("Modèle chargé depuis le fichier")
    else:
        logger.info("Entraînement du modèle...")
        model = train_new_model()
        joblib.dump(model, model_path)
        logger.info("Modèle entraîné et sauvegardé")

    # Charger le dataset pour les colonnes
    dataset = load_dataset()
    feature_columns = [
        "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets"
    ]

    return model, feature_columns, dataset


def load_dataset():
    """Charge et préprocess le dataset"""
    try:
        dataset = pd.read_csv("Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
        dataset.columns = dataset.columns.str.strip()

        keep_cols = [
            "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Label"
        ]

        dataset = dataset[keep_cols].dropna().drop_duplicates()
        dataset = dataset[dataset['Label'].isin(['BENIGN', 'DoS Hulk', 'DDoS'])]
        dataset['Label'] = dataset['Label'].apply(
            lambda x: 'attack' if x != 'BENIGN' else 'normal'
        )

        return dataset

    except FileNotFoundError:
        st.error("Dataset non trouvé: Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv")
        return pd.DataFrame()


def train_new_model():
    """Entraîne un nouveau modèle"""
    dataset = load_dataset()

    if dataset.empty:
        raise ValueError("Dataset vide, impossible d'entraîner le modèle")

    X = dataset.drop(columns='Label')
    y = dataset['Label']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    # Paramètres pour la recherche
    param_grid = {
        'n_estimators': [50, 100, 150],
        'max_depth': [5, 10, 20, None],
        'min_samples_split': [2, 5, 10],
        'min_samples_leaf': [1, 2, 4],
        'bootstrap': [True, False]
    }

    rf = RandomForestClassifier(random_state=42)
    search = RandomizedSearchCV(
        rf, param_distributions=param_grid, n_iter=10, cv=3,
        scoring='accuracy', n_jobs=-1, random_state=42
    )

    search.fit(X_train, y_train)

    # Évaluation
    y_pred = search.best_estimator_.predict(X_test)
    report = classification_report(y_test, y_pred, output_dict=True)

    logger.info(f"Précision du modèle: {report['attack']['precision']:.4f}")

    return search.best_estimator_


def init_session_state():
    """Initialise le session state"""
    if 'alerts' not in st.session_state:
        st.session_state.alerts = []
    if 'monitoring_active' not in st.session_state:
        st.session_state.monitoring_active = False
    if 'alert_queue' not in st.session_state:
        st.session_state.alert_queue = queue.Queue(maxsize=1000)
    if 'analyzer' not in st.session_state:
        st.session_state.analyzer = None


def update_alerts_from_queue():
    """Met à jour les alertes depuis la queue thread-safe"""
    try:
        while True:
            alert = st.session_state.alert_queue.get_nowait()
            st.session_state.alerts.append(alert)
    except queue.Empty:
        pass


def display_sidebar_charts(dataset, model, feature_columns):
    """Affiche les graphiques dans la sidebar"""
    if dataset.empty:
        return

    with st.sidebar.expander("Répartition ATK/NORMAL", expanded=False):
        label_counts = dataset['Label'].value_counts()
        fig, ax = plt.subplots(figsize=(6, 4))
        ax.pie(label_counts.values, labels=label_counts.index, autopct='%1.1f%%', startangle=90)
        ax.axis('equal')
        st.pyplot(fig)

    with st.sidebar.expander("Importance des variables", expanded=False):
        param_important = model.feature_importances_
        serie_panda = pd.Series(param_important, index=feature_columns).sort_values(ascending=True)
        figure_fi, axe_fi = plt.subplots(figsize=(8, 5))
        serie_panda.plot(kind='barh', ax=axe_fi)
        axe_fi.set_title("Importance des variables")
        axe_fi.set_xlabel("Importance")
        st.pyplot(figure_fi)


def main():
    """Fonction principale de l'application"""
    st.set_page_config(
        page_title="Jeanne D'Arc - Détecteur d'Attaques",
        page_icon="🛡️",
        layout="wide"
    )

    st.title("🛡️ Jeanne D'Arc - Détecteur d'Attaques Réseau")

    # Initialisation
    init_session_state()

    try:
        model, feature_columns, dataset = load_model()
    except Exception as e:
        st.error(f"Erreur chargement modèle: {e}")
        return

    # Sidebar avec graphiques
    display_sidebar_charts(dataset, model, feature_columns)

    # Interface principale
    col1, col2, col3 = st.columns([1, 1, 1])

    with col1:
        if st.button("🚀 Démarrer Surveillance", disabled=st.session_state.monitoring_active):
            if st.session_state.analyzer is None:
                st.session_state.analyzer = GestionNetwork(
                    model, feature_columns, st.session_state.alert_queue
                )

            st.session_state.analyzer.start_analyse()
            st.session_state.monitoring_active = True
            st.success("Surveillance démarrée!")
            st.rerun()

    with col2:
        if st.button("⏹️ Arrêter Surveillance", disabled=not st.session_state.monitoring_active):
            if st.session_state.analyzer:
                st.session_state.analyzer.stop_analyse()
            st.session_state.monitoring_active = False
            st.success("Surveillance arrêtée!")
            st.rerun()

    with col3:
        if st.button("🧪 Test Attaque Simulée"):
            fake_data = AttackSimulator.get_fake_attack_data()
            try:
                df = pd.DataFrame([fake_data], columns=feature_columns)
                prediction = model.predict(df)[0]

                if prediction == "attack":
                    st.success("✅ Détection OK sur attaque simulée")
                else:
                    st.warning("❌ Détection ratée sur attaque simulée")
            except Exception as e:
                st.error(f"Erreur test: {e}")

    # Bouton attaque réelle (dangereux)
    with st.expander("⚠️ Attaque Réelle (Dangereux) (Linux Only)", expanded=False):
        st.warning("Cette fonction lance une vraie attaque SYN flood!")
        target_ip = st.text_input("IP Cible", value=GLOBAL_IP_CIBLE)

        if st.button("🔥 Lancer Attaque SYN Flood"):
            try:
                AttackSimulator.launch_syn_flood(target_ip)
                st.success("Attaque lancée (3 secondes)")
            except Exception as e:
                st.error(f"Erreur attaque: {e}")

    # Statut
    if st.session_state.monitoring_active:
        st.success("🟢 Surveillance Active")
    else:
        st.info("🔴 Surveillance Inactive")

    # Mise à jour des alertes
    update_alerts_from_queue()

    # Affichage des alertes
    st.divider()

    with st.expander("🚨 Alertes en Temps Réel", expanded=True):
        if st.session_state.alerts:
            # Affiche les 20 dernières alertes
            recent_alerts = list(reversed(st.session_state.alerts[-20:]))

            for alert in recent_alerts:
                if isinstance(alert, dict):
                    timestamp = alert.get('timestamp', 'N/A')
                    message = alert.get('message', 'N/A')
                    alert_type = alert.get('type', 'info')

                    if alert_type == 'attack':
                        st.error(f"🚨 {timestamp}: {message}")
                    elif alert_type == 'error':
                        st.warning(f"⚠️ {timestamp}: {message}")
                    else:
                        st.info(f"ℹ️ {timestamp}: {message}")
                else:
                    # Compatibilité avec ancien format
                    st.write(alert)
        else:
            st.info("Aucune alerte pour le moment")

    # Auto-refresh si surveillance active
    if st.session_state.monitoring_active:
        time.sleep(2)
        st.rerun()


if __name__ == "__main__":
    main()