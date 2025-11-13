#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script Machine A - Envoi de fichier chiffré via IPFS

Ce script :
1. Chiffre un fichier avec AES-256
2. Génère et sauvegarde une clé de chiffrement
3. Ajoute le fichier chiffré à IPFS
4. Affiche le CID pour partage avec Machine B
5. Calcule et affiche le hash SHA256 du fichier original
"""

import os
import sys
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import ipfshttpclient


# Configuration
IPFS_ADDRESS = "/dns/localhost/tcp/5001/http"  # Adresse du démon IPFS (paramétrable)
KEY_FILE = "key.txt"  # Fichier contenant la clé de chiffrement
TEST_FILE = "test.txt"  # Fichier à envoyer


def generate_key():
    """
    Génère une clé AES-256 (32 bytes = 256 bits) aléatoire.
    
    Returns:
        bytes: Clé de 32 bytes
    """
    return secrets.token_bytes(32)


def save_key(key, filename=KEY_FILE):
    """
    Sauvegarde la clé de chiffrement dans un fichier (format hexadécimal).
    
    Args:
        key (bytes): Clé à sauvegarder
        filename (str): Nom du fichier de sortie
    """
    try:
        with open(filename, 'w') as f:
            f.write(key.hex())
        print(f"✓ Clé sauvegardée dans '{filename}'")
        print(f"  (À transférer manuellement à Machine B)")
    except Exception as e:
        print(f"✗ Erreur lors de la sauvegarde de la clé : {e}")
        sys.exit(1)


def encrypt_file(filepath, key):
    """
    Chiffre un fichier avec AES-256 en mode CBC.
    
    Args:
        filepath (str): Chemin vers le fichier à chiffrer
        key (bytes): Clé de chiffrement (32 bytes)
    
    Returns:
        bytes: Données chiffrées
    """
    try:
        # Lire le fichier original
        with open(filepath, 'rb') as f:
            plaintext = f.read()
        
        # Générer un IV (Initialization Vector) aléatoire (16 bytes pour AES)
        iv = secrets.token_bytes(16)
        
        # Créer le cipher AES-256-CBC
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Ajouter du padding PKCS7 manuellement si nécessaire
        # (cryptography le fait automatiquement, mais on s'assure que la taille est multiple de 16)
        pad_length = 16 - (len(plaintext) % 16)
        plaintext_padded = plaintext + bytes([pad_length] * pad_length)
        
        # Chiffrer
        ciphertext = encryptor.update(plaintext_padded) + encryptor.finalize()
        
        # Préfixer l'IV au ciphertext (nécessaire pour le déchiffrement)
        encrypted_data = iv + ciphertext
        
        print(f"✓ Fichier chiffré : {len(encrypted_data)} bytes")
        return encrypted_data
        
    except FileNotFoundError:
        print(f"✗ Erreur : Fichier '{filepath}' introuvable")
        sys.exit(1)
    except Exception as e:
        print(f"✗ Erreur lors du chiffrement : {e}")
        sys.exit(1)


def calculate_sha256(filepath):
    """
    Calcule le hash SHA256 d'un fichier.
    
    Args:
        filepath (str): Chemin vers le fichier
    
    Returns:
        str: Hash SHA256 en hexadécimal
    """
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        return sha256_hash.hexdigest()
    except Exception as e:
        print(f"✗ Erreur lors du calcul du hash : {e}")
        return None


def add_to_ipfs(data, ipfs_address=IPFS_ADDRESS):
    """
    Ajoute des données à IPFS.
    
    Args:
        data (bytes): Données à ajouter
        ipfs_address (str): Adresse du démon IPFS
    
    Returns:
        str: CID (Content Identifier) du fichier ajouté
    """
    try:
        print(f"Connexion au démon IPFS à {ipfs_address}...")
        client = ipfshttpclient.connect(ipfs_address)
        
        print("Ajout du fichier chiffré à IPFS...")
        result = client.add_bytes(data)
        
        print(f"✓ Fichier ajouté à IPFS")
        return result
        
    except ipfshttpclient.exceptions.ConnectionError:
        print(f"✗ Erreur : Impossible de se connecter au démon IPFS à {ipfs_address}")
        print("  Vérifiez que le démon IPFS est lancé : ipfs daemon")
        sys.exit(1)
    except Exception as e:
        print(f"✗ Erreur lors de l'ajout à IPFS : {e}")
        sys.exit(1)


def main():
    """
    Fonction principale : orchestre le chiffrement et l'upload vers IPFS.
    """
    print("=" * 60)
    print("MACHINE A - Envoi de fichier chiffré via IPFS")
    print("=" * 60)
    print()
    
    # Vérifier que le fichier test existe
    if not os.path.exists(TEST_FILE):
        print(f"✗ Erreur : Le fichier '{TEST_FILE}' n'existe pas")
        print(f"  Créez d'abord un fichier '{TEST_FILE}' à envoyer")
        sys.exit(1)
    
    # Étape 1 : Calculer le hash SHA256 du fichier original (pour vérification)
    print(f"Étape 1 : Calcul du hash SHA256 de '{TEST_FILE}'...")
    original_hash = calculate_sha256(TEST_FILE)
    if original_hash:
        print(f"✓ Hash SHA256 du fichier original : {original_hash}")
    print()
    
    # Étape 2 : Générer la clé de chiffrement
    print("Étape 2 : Génération de la clé de chiffrement AES-256...")
    key = generate_key()
    save_key(key)
    print()
    
    # Étape 3 : Chiffrer le fichier
    print(f"Étape 3 : Chiffrement de '{TEST_FILE}'...")
    encrypted_data = encrypt_file(TEST_FILE, key)
    print()
    
    # Étape 4 : Ajouter à IPFS
    print("Étape 4 : Ajout du fichier chiffré à IPFS...")
    cid = add_to_ipfs(encrypted_data)
    print()
    
    # Résumé final
    print("=" * 60)
    print("RÉSUMÉ")
    print("=" * 60)
    print(f"Fichier original     : {TEST_FILE}")
    print(f"Hash SHA256          : {original_hash}")
    print(f"CID IPFS             : {cid}")
    print(f"Fichier clé          : {KEY_FILE}")
    print()
    print("→ Transférez manuellement le CID et le fichier 'key.txt' à Machine B")
    print("=" * 60)


if __name__ == "__main__":
    main()

