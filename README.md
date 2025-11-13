# Système P2P d'Échange de Fichiers Chiffrés

Un système P2P sécurisé pour échanger des fichiers chiffrés en chunks entre deux machines sur le même réseau local, **sans mot de passe**, mais avec une sécurité maximale via HTTPS et mTLS.

## 🔐 Fonctionnalités

- ✅ **Découpage automatique** des fichiers en chunks (taille configurable, 1 Mo par défaut)
- ✅ **Chiffrement AES-256** de chaque chunk avant transmission
- ✅ **Vérification d'intégrité** avec SHA256 pour chaque chunk
- ✅ **Communication sécurisée** via HTTPS avec authentification mutuelle (mTLS)
- ✅ **Certificats SSL** signés par une CA locale
- ✅ **API REST** FastAPI pour l'échange de chunks
- ✅ **Client P2P** intégré pour envoyer/télécharger des fichiers complets
- ✅ **Gestion d'erreurs** robuste (connexion, chunks manquants, hash incorrect)

## 📋 Prérequis

- Python 3.8 ou supérieur
- Deux machines sur le même réseau local
- Les deux machines doivent pouvoir communiquer (firewall configuré)

## 🚀 Installation

### 1. Cloner ou télécharger le projet

```bash
# Sur les deux machines
cd "test réseau"
```

### 2. Installer les dépendances

```bash
pip install -r requirements.txt
```

### 3. Générer les certificats SSL

**⚠️ IMPORTANT : Exécutez cette étape sur UNE SEULE machine, puis copiez le dossier `certs/` sur l'autre machine.**

```bash
python generate_certs.py
```

Cela génère :
- `certs/ca-cert.pem` - Certificat de l'autorité de certification
- `certs/ca-key.pem` - Clé privée de la CA (à garder secrète)
- `certs/server-cert.pem` - Certificat serveur
- `certs/server-key.pem` - Clé privée serveur
- `certs/client-cert.pem` - Certificat client
- `certs/client-key.pem` - Clé privée client

**Copiez le dossier `certs/` complet sur la deuxième machine.**

## 📖 Utilisation

### Sur chaque machine

1. **Lancez le script** :

```bash
python p2p_file_exchange.py
```

2. **Configurez le serveur** :
   - Entrez le port (par défaut : 8443)
   
3. **Configurez le pair** :
   - Entrez l'adresse IP de l'autre machine (ex: `192.168.1.100`)
   - Entrez le port du pair (par défaut : 8443)

4. **Configurez le chiffrement** :
   - Entrez un mot de passe pour le chiffrement (ou appuyez sur Entrée pour une clé aléatoire)
   - **⚠️ Les deux machines doivent utiliser le MÊME mot de passe pour pouvoir déchiffrer les fichiers**

### Menu principal

```
1. Envoyer un fichier à un pair
   → Découpe le fichier en chunks
   → Chiffre chaque chunk
   → Envoie les chunks au pair

2. Télécharger un fichier depuis un pair
   → Télécharge les chunks depuis le pair
   → Vérifie l'intégrité de chaque chunk
   → Déchiffre et reconstitue le fichier

3. Lister les chunks locaux
   → Affiche tous les chunks stockés localement

4. Lister les chunks du pair
   → Affiche tous les chunks disponibles sur le pair

5. Quitter
```

## 🔧 Architecture

### Structure des dossiers

```
.
├── p2p_file_exchange.py    # Script principal
├── generate_certs.py        # Générateur de certificats
├── requirements.txt         # Dépendances Python
├── README.md               # Ce fichier
├── certs/                  # Certificats SSL (à générer)
│   ├── ca-cert.pem
│   ├── ca-key.pem
│   ├── server-cert.pem
│   ├── server-key.pem
│   ├── client-cert.pem
│   └── client-key.pem
├── chunks/                 # Chunks chiffrés stockés localement
└── received/               # Fichiers reconstitués après téléchargement
```

### Flux d'envoi de fichier

1. **Découpage** : Le fichier est découpé en chunks de 1 Mo
2. **Chiffrement** : Chaque chunk est chiffré avec AES-256
3. **Hash** : Un hash SHA256 est calculé pour chaque chunk chiffré
4. **Stockage local** : Les chunks sont sauvegardés localement dans `chunks/`
5. **Envoi** : Chaque chunk est envoyé au pair via HTTPS avec mTLS
6. **Vérification** : Le pair vérifie le hash de chaque chunk reçu

### Flux de téléchargement de fichier

1. **Métadonnées** : Les métadonnées du fichier (liste des chunks) sont nécessaires
2. **Téléchargement** : Chaque chunk est téléchargé depuis le pair
3. **Vérification** : Le hash de chaque chunk est vérifié
4. **Stockage local** : Les chunks sont sauvegardés localement
5. **Déchiffrement** : Chaque chunk est déchiffré
6. **Reconstitution** : Le fichier est reconstitué à partir des chunks déchiffrés
7. **Vérification finale** : La taille du fichier reconstitué est vérifiée

## 🔒 Sécurité

### Authentification mutuelle (mTLS)

- Chaque machine possède un certificat client signé par la CA locale
- Le serveur vérifie que le certificat client est signé par la CA
- Le client vérifie que le certificat serveur est signé par la CA
- **Aucune communication n'est possible sans certificat valide**

### Chiffrement

- **AES-256** pour le chiffrement des chunks
- Clé dérivée à partir d'un mot de passe (PBKDF2 avec 100 000 itérations)
- Chaque chunk est chiffré indépendamment

### Intégrité

- **SHA256** pour vérifier l'intégrité de chaque chunk
- Vérification du hash à chaque réception de chunk
- Vérification de la taille finale du fichier reconstitué

## ⚠️ Limitations et Notes

1. **Métadonnées des fichiers** : Pour télécharger un fichier, vous devez connaître les métadonnées (liste des chunks). Dans une version future, on pourrait ajouter un système de catalogue partagé.

2. **Clé de chiffrement** : Les deux machines doivent utiliser le même mot de passe pour le chiffrement. En production, on pourrait implémenter un échange de clés Diffie-Hellman.

3. **Certificats** : Les certificats sont auto-signés par une CA locale. Pour un usage en production, utilisez une CA reconnue.

4. **Réseau local uniquement** : Ce système est conçu pour fonctionner sur un réseau local. Pour un usage sur Internet, des modifications seraient nécessaires.

## 🐛 Dépannage

### Erreur : "Certificats manquants"
→ Exécutez `python generate_certs.py` et copiez le dossier `certs/` sur les deux machines.

### Erreur : "Connection refused" ou timeout
→ Vérifiez que :
- Le serveur est bien démarré sur l'autre machine
- L'adresse IP et le port sont corrects
- Le firewall autorise les connexions sur le port utilisé

### Erreur : "Échec du déchiffrement"
→ Vérifiez que les deux machines utilisent le même mot de passe pour le chiffrement.

### Erreur : "Hash invalide"
→ Le chunk a été corrompu pendant la transmission. Réessayez l'envoi.

## 📝 Exemple d'utilisation

### Machine A (192.168.1.100)

```bash
python p2p_file_exchange.py
# Port: 8443
# Pair: 192.168.1.101:8443
# Mot de passe: monMotDePasseSecret
```

### Machine B (192.168.1.101)

```bash
python p2p_file_exchange.py
# Port: 8443
# Pair: 192.168.1.100:8443
# Mot de passe: monMotDePasseSecret
```

### Envoyer un fichier depuis A vers B

1. Sur la machine A : Menu → `1` → Chemin du fichier
2. Le fichier est découpé, chiffré et envoyé à B
3. Les chunks sont stockés sur B dans `chunks/`

### Télécharger un fichier depuis B vers A

1. Sur la machine A : Menu → `2` → Métadonnées du fichier
2. Les chunks sont téléchargés depuis B
3. Le fichier est déchiffré et reconstitué dans `received/`

## 📄 Licence

Ce projet est fourni à des fins éducatives et de démonstration.

## 🤝 Contribution

Les améliorations sont les bienvenues ! N'hésitez pas à proposer des fonctionnalités comme :
- Catalogue partagé des fichiers disponibles
- Échange de clés Diffie-Hellman
- Interface graphique
- Support multi-pairs (plus de 2 machines)

