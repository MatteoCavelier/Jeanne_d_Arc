import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

url = "https://raw.githubusercontent.com/defcom17/NSL_KDD/master/KDDTrain+.txt"
columns = ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes", "land", "wrong_fragment", "urgent", "hot",
           "num_failed_logins", "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root", "num_file_creations",
           "num_shells", "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login", "count", "srv_count",
           "serror_rate", "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
           "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate", "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
           "dst_host_srv_diff_host_rate", "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate", "label"]

print(len(columns))

dataset = pd.read_csv(url, names=columns)

dataset["dst_host_srv_rerror_rate"], _ = pd.factorize(dataset["dst_host_srv_rerror_rate"])

dataset.dropna(inplace=True)

dataset.drop_duplicates(inplace=True)

if dataset['duration'].dtype == 'object':
    dataset['duration'] = pd.to_numeric(dataset['duration'], errors='coerce')

categorical_cols = ["protocol_type", "service", "flag"]
for col in categorical_cols:
    dataset[col] = pd.factorize(dataset[col])[0]

X = dataset.drop(columns=["label"], axis=1)
Y = dataset["label"]

X_train, X_test, Y_train, Y_test = train_test_split(X, Y, test_size=0.2, random_state=42)

model_RF = RandomForestClassifier(n_estimators=100)
model_RF.fit(X_train, Y_train)

score = model_RF.score(X_test, Y_test)
print("Score du modèle :", score)


def classifier(model, **kwargs):
    feature_names = X.columns

    default_values = X.mean().to_dict()

    input_data = {feature: kwargs.get(feature, default_values.get(feature, 0)) for feature in feature_names}

    x = pd.DataFrame([input_data], columns=feature_names)

    prediction = model.predict(x)
    print("Prédiction :", prediction)
    return prediction


classifier(model_RF, duration=1, src_bytes=500)
