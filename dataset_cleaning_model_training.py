import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pickle

url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
columns = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land",
           "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in", "num_compromised",
           "root_shell", "su_attempted", "num_root", "num_file_creations", "num_shells",
           "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count",
           "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate",
           "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_count",
           "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
           "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
           "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"]

print("📦 Chargement du dataset...")
dataset = pd.read_csv(url, names=columns)

relevant_columns = ["duration", "protocol_type", "src_bytes", "dst_bytes", "flag", "count",
                    "srv_count", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "label"]
dataset = dataset[relevant_columns]

dataset.dropna(inplace=True)
dataset.drop_duplicates(inplace=True)

if dataset["duration"].dtype == "object":
    dataset["duration"] = pd.to_numeric(dataset["duration"], errors="coerce")
if dataset["src_bytes"].dtype == "object":
    dataset["src_bytes"] = pd.to_numeric(dataset["src_bytes"], errors="coerce")
if dataset["dst_bytes"].dtype == "object":
    dataset["dst_bytes"] = pd.to_numeric(dataset["dst_bytes"], errors="coerce")

for col in ["protocol_type", "flag"]:
    dataset[col] = pd.factorize(dataset[col])[0]

X = dataset.drop("label", axis=1)
y = dataset["label"]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model_RF = RandomForestClassifier(n_estimators=100, random_state=42)
model_RF.fit(X_train, y_train)

score = model_RF.score(X_test, y_test)
print("✅ Score du modèle :", score)

# Sauvegarde du modèle
with open("model_RF.pkl", "wb") as f:
    pickle.dump(model_RF, f)
    print("✅ Modèle sauvegardé dans model_RF.pkl")