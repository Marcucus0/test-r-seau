# Échange de fichiers sécurisé via IPFS

Ce projet permet d'échanger des fichiers entre deux machines sur le même réseau via IPFS, avec chiffrement AES-256 pour assurer la confidentialité.

## Prérequis

1. **IPFS installé et démon lancé** sur chaque machine :
   ```bash
   # Installer IPFS (si pas déjà fait)
   # Télécharger depuis https://dist.ipfs.io/#go-ipfs
   
   # Initialiser IPFS (première fois seulement)
   ipfs init
   
   # Lancer le démon IPFS
   ipfs daemon
   ```

2. **Python 3.7+** installé

3. **Bibliothèques Python** :
   ```bash
   pip install -r requirements.txt
   ```

## Structure des fichiers

- `machine_a.py` : Script pour envoyer un fichier chiffré via IPFS
- `machine_b.py` : Script pour récupérer et déchiffrer un fichier depuis IPFS
- `test.txt` : Fichier de test à envoyer
- `key.txt` : Clé de chiffrement (générée par Machine A, à transférer manuellement)
- `requirements.txt` : Dépendances Python

## Utilisation

### Sur Machine A (expéditeur)

1. Assurez-vous que le démon IPFS est lancé :
   ```bash
   ipfs daemon
   ```

2. Placez le fichier à envoyer dans `test.txt` (ou modifiez `TEST_FILE` dans le script)

3. Exécutez le script :
   ```bash
   python machine_a.py
   ```

4. Le script va :
   - Calculer le hash SHA256 du fichier original
   - Générer une clé de chiffrement AES-256
   - Sauvegarder la clé dans `key.txt`
   - Chiffrer le fichier
   - L'ajouter à IPFS
   - Afficher le CID

5. **Transférez manuellement** à Machine B :
   - Le **CID** affiché
   - Le fichier **`key.txt`**

### Sur Machine B (récepteur)

1. Assurez-vous que le démon IPFS est lancé :
   ```bash
   ipfs daemon
   ```

2. Placez le fichier `key.txt` dans le même répertoire que `machine_b.py`

3. Exécutez le script :
   ```bash
   python machine_b.py
   ```

4. Entrez le CID lorsque demandé (ou passez-le en argument) :
   ```bash
   python machine_b.py <CID>
   ```

5. Entrez le hash SHA256 original pour vérification (optionnel)

6. Le script va :
   - Lire la clé depuis `key.txt`
   - Récupérer le fichier chiffré depuis IPFS
   - Déchiffrer le fichier
   - Sauvegarder le fichier déchiffré
   - Vérifier l'intégrité avec SHA256

## Configuration

### Adresse IPFS

Par défaut, les scripts utilisent `/dns/localhost/tcp/5001/http`. Pour utiliser une autre adresse, modifiez la variable `IPFS_ADDRESS` dans les scripts :

```python
IPFS_ADDRESS = "/ip4/192.168.1.100/tcp/5001/http"  # Exemple pour une IP spécifique
```

### Fichiers

- `TEST_FILE` dans `machine_a.py` : nom du fichier à envoyer
- `OUTPUT_FILE` dans `machine_b.py` : nom du fichier déchiffré sauvegardé
- `KEY_FILE` : nom du fichier contenant la clé (par défaut `key.txt`)

## Sécurité

- **Chiffrement AES-256-CBC** : Fichiers chiffrés avec une clé de 256 bits
- **IV aléatoire** : Chaque fichier utilise un IV unique
- **Transfert manuel de la clé** : La clé n'est jamais transmise via IPFS
- **Vérification d'intégrité** : Hash SHA256 pour détecter toute altération

## Dépannage

### Erreur de connexion IPFS
- Vérifiez que le démon IPFS est lancé : `ipfs daemon`
- Vérifiez l'adresse IPFS dans les scripts
- Vérifiez que les deux machines peuvent communiquer sur le réseau

### Erreur de déchiffrement
- Vérifiez que le fichier `key.txt` est identique sur les deux machines
- Vérifiez que le CID est correct

### Fichier introuvable sur IPFS
- Assurez-vous que les deux machines sont sur le même réseau IPFS
- Vérifiez que le CID est correct
- Attendez quelques secondes après l'ajout sur Machine A avant de récupérer sur Machine B

