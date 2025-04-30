from dataset_cleaning_model_training import train_model, classifier

model_RF, feature_columns = train_model()

def predict_from_packet(packet):
    try:
        data = {
            "duration": 1,
            "protocol_type": packet.proto if hasattr(packet, "proto") else 0,
            "src_bytes": len(packet),
            "dst_bytes": 0,
            "flag": 0,
            "count": 1,
            "srv_count": 1,
            "same_srv_rate": 0.5,
            "diff_srv_rate": 0.5,
            "srv_diff_host_rate": 0.5,
        }
        pred = classifier(model_RF, **data)
        return pred[0]
    except Exception as e:
        print(f"Erreur de prédiction : {e}")
        return "Erreur"