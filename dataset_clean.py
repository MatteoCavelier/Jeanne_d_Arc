import pandas as pd
import numpy as np
import seaborn as sns
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelEncoder

# Téléchargement et chargement du dataset NSL-KDD
url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
columns = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot", 
           "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations", 
           "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count", "srv_count", 
           "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", 
           "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", 
           "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"]

df = pd.read_csv(url, names=columns)

# Afficher la taille initiale du dataset
print(f"Taille du dataset avant nettoyage : {df.shape}")

# Nettoyage des données (suppression des doublons, gestion des valeurs manquantes)
df.drop_duplicates(inplace=True)
df.dropna(inplace=True)

# Afficher la taille après nettoyage
print(f"Taille du dataset après nettoyage : {df.shape}")

# Afficher la distribution des classes
distribution = df['label'].value_counts()
print("Distribution des classes d'attaques :")
print(distribution)

# Création d'un dictionnaire des attaques avec leurs indices
attack_labels = {
    0: 'normal', 1: 'neptune', 2: 'warezclient', 3: 'ipsweep', 4: 'portsweep', 5: 'satan', 
    6: 'smurf', 7: 'pod', 8: 'nmap', 9: 'back', 10: 'teardrop', 11: 'guess_passwd', 
    12: 'buffer_overflow', 13: 'rootkit', 14: 'perl', 15: 'loadmodule', 16: 'ftp_write', 
    17: 'multihop', 18: 'phf', 19: 'spy', 20: 'imap'
}

# Affichage des types d'attaques connus et leur description
print("\nTypes d'attaques et descriptions :")
for attack, description in attack_labels.items():  # Remplacer attack_types par attack_labels
    count = distribution.get(str(attack), 0)  # Utiliser str(attack) pour correspondre aux indices
    print(f"{attack}: {description} ({count} occurrences)")

# Séparation des features et des labels
X = df.drop(columns=['label'])
y = df['label']

# Séparation en données d'entraînement et de test
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
print(f"Taille des données d'entraînement : {X_train.shape}")
print(f"Taille des données de test : {X_test.shape}")

# Identifier les colonnes catégoriques
categorical_columns = X_train.select_dtypes(include=['object']).columns

# Encoder les valeurs catégoriques en nombres
label_encoders = {}
for col in categorical_columns:
    le = LabelEncoder()
    X_train[col] = le.fit_transform(X_train[col])
    X_test[col] = le.transform(X_test[col])  # Transformer selon le même encodage
    label_encoders[col] = le  # Stocker l'encodeur si besoin plus tard

# Normalisation des données
scaler = StandardScaler()
X_train = scaler.fit_transform(X_train)
X_test = scaler.transform(X_test)

# Affichage d'une visualisation des classes avec légendes et les noms des attaques
plt.figure(figsize=(10, 5))  # Taille du graphique d'origine
sns.barplot(x=distribution.index, y=distribution.values)

# Ajouter des légendes sur chaque barre avec les noms des attaques
plt.xticks(ticks=np.arange(len(distribution.index)), labels=[attack_labels.get(i, f'Unknown {i}') for i in distribution.index], rotation=90, fontsize=8)
plt.xlabel("Type d'attaque", fontsize=10)
plt.ylabel("Nombre d'occurrences", fontsize=10)
plt.title("Distribution des types d'attaques", fontsize=12)

# Ajouter des annotations pour les valeurs avec une police plus petite
for i, count in enumerate(distribution.values):
    plt.text(i, count + 50, str(count), ha='center', va='bottom', fontsize=8)

# Ajuster la taille du graphique et réduire l'espace autour
plt.subplots_adjust(left=0.05, right=0.95, top=0.95, bottom=0.15)

plt.show()
