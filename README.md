
# Documentation Technique : Détection d'attaques réseau

## Introduction

Ce projet utilise un modèle de machine learning pour détecter des attaques réseau en temps réel à partir de paquets capturés sur un réseau. Il est construit avec **Streamlit** pour l'interface utilisateur, **Scapy** pour la capture et l'analyse des paquets réseau, et un **Random Forest Classifier** pour la détection d'attaques.

## Prérequis

### Python

Assurez-vous d'avoir **Python 3.7+** installé sur votre machine.

### Bibliothèques nécessaires

Les bibliothèques suivantes sont nécessaires pour faire fonctionner l'application. Vous pouvez les installer avec `pip` :

```bash
pip install streamlit scapy pandas scikit-learn matplotlib
````

### Fichier CSV pour l'entraînement du modèle

Le modèle utilise un fichier CSV spécifique pour l'entraînement. Téléchargez le fichier suivant et placez-le dans le même répertoire que votre script :

* `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`

## Installation

### 1. Cloner le repository

Clonez le repository contenant le code du projet (ou placez simplement le code dans votre répertoire local) :

```bash
git clone https://url-du-repository.git
cd repertoire-du-projet
```

### 2. Installer les dépendances

Installez les bibliothèques nécessaires avec pip :

```bash
pip install -r requirements.txt
```

> Remarque : Si vous n'avez pas de fichier `requirements.txt`, vous pouvez simplement installer les packages manuellement comme indiqué plus haut.

### 3. Préparer le fichier CSV

Téléchargez le fichier CSV nécessaire pour entraîner le modèle de détection d'attaques à partir du lien fourni et placez-le dans le répertoire de votre projet sous le nom exact : `Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`.

### 4. Lancer l'application

Exécutez l'application Streamlit avec la commande suivante :

```bash
streamlit run votre_script.py
```

Cela ouvrira une page dans votre navigateur où vous pourrez interagir avec l'application.

## Fonctionnalités

### 1. **Surveillance des paquets réseau**

Lorsque vous lancez la surveillance, le programme capture les paquets réseau en temps réel sur l'interface spécifiée et en analyse les caractéristiques. Si une attaque est détectée (DoS, DDoS, etc.), une alerte est générée dans l'interface utilisateur.

### 2. **Simulation d'attaque**

L'application permet de simuler une attaque (SYN flood) pour tester le modèle de détection en envoyant des paquets spécifiques à une machine cible.

### 3. **Analyse du modèle**

Le modèle utilise un **Random Forest Classifier** qui a été optimisé avec une recherche aléatoire sur des hyperparamètres. Les résultats du modèle (précision, confusion matrix, etc.) sont affichés dans la barre latérale de l'interface.

### 4. **Graphiques**

Deux graphiques sont générés dans la barre latérale :

* **Répartition des attaques et des connexions normales** : Affiche la proportion d'attaques et de connexions normales.
* **Importance des variables** : Affiche un graphique en barres horizontales montrant l'importance des différentes caractéristiques utilisées par le modèle.

### 5. **Alertes**

Les alertes liées à la détection des attaques sont affichées dans la section dédiée à l'interface, avec les détails de chaque attaque détectée.

### 6. **Simulation d'une attaque manuelle**

Il est possible d'envoyer une attaque SYN flood manuellement vers une machine cible spécifiée.

## Fonctionnement du Code

### 1. **Chargement et entraînement du modèle**

Le modèle est chargé et entraîné à partir des données contenues dans le fichier CSV. L'entraînement utilise un **Random Forest Classifier**, et les hyperparamètres sont optimisés à l'aide d'une recherche aléatoire (`RandomizedSearchCV`).

### 2. **Capture des paquets avec Scapy**

Le code utilise **Scapy** pour capturer les paquets réseau en temps réel. Lorsqu'un paquet est capturé, des informations sont extraites et analysées par le modèle. Si une attaque est détectée, une alerte est générée.

### 3. **Prédiction d'attaque**

Lors de la capture des paquets, un échantillon est créé avec des caractéristiques spécifiques (durée du flux, nombre de paquets, etc.) et est passé au modèle pour effectuer une prédiction. Si une attaque est détectée, l'alerte est enregistrée.

### 4. **Simulation d'attaque SYN flood**

Le code peut envoyer une attaque SYN flood (attaque DoS) à une machine cible spécifique, avec un nombre configurable de paquets.

## Interface Utilisateur

L'interface utilisateur est construite avec **Streamlit**, offrant une expérience interactive avec les fonctionnalités suivantes :

* **Lancer la surveillance** : Démarre la capture des paquets réseau.
* **Simuler une attaque (test modèle)** : Simule une attaque pour tester le modèle de détection.
* **Envoyer manuel ATK** : Envoie une attaque SYN flood à une adresse IP spécifiée.

Les alertes et les résultats des prédictions sont affichés dans la section "Alertes" de l'interface.

## Sécurités et Remarques

* Assurez-vous que l'interface réseau sur laquelle vous capturez les paquets est correctement configurée et accessible.
* Ne testez pas l'envoi d'attaques à des machines non autorisées ou dans un environnement de production.
* Ce projet est destiné à des fins de test et d'apprentissage.

## Conclusion

Ce projet offre une solution simple pour détecter des attaques réseau en utilisant le machine learning et l'analyse de paquets en temps réel. Vous pouvez étendre et adapter le code selon vos besoins en ajoutant d'autres types d'attaques ou en améliorant le modèle de détection.

