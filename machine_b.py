#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script Machine B - Récupération et déchiffrement de fichier depuis IPFS

Ce script :
1. Récupère un fichier chiffré depuis IPFS en utilisant un CID
2. Lit la clé de chiffrement depuis un fichier
3. Déchiffre le fichier
4. Sauvegarde le fichier déchiffré
5. Vérifie l'intégrité avec SHA256 (si le hash original est fourni)
"""

import os
import sys
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import ipfshttpclient


# Configuration
IPFS_ADDRESS = "/dns/localhost/tcp/5001/http"  # Adresse du démon IPFS (paramétrable)
KEY_FILE = "key.txt"  # Fichier contenant la clé de chiffrement
OUTPUT_FILE = "received_file.txt"  # Nom du fichier déchiffré sauvegardé


def read_key(filename=KEY_FILE):
    """
    Lit la clé de chiffrement depuis un fichier (format hexadécimal).
    
    Args:
        filename (str): Nom du fichier contenant la clé
    
    Returns:
        bytes: Clé de 32 bytes
    """
    try:
        with open(filename, 'r') as f:
            key_hex = f.read().strip()
        key = bytes.fromhex(key_hex)
        
        if len(key) != 32:
            print(f"✗ Erreur : La clé doit faire 32 bytes (256 bits), trouvé {len(key)} bytes")
            sys.exit(1)
        
        print(f"✓ Clé lue depuis '{filename}'")
        return key
        
    except FileNotFoundError:
        print(f"✗ Erreur : Fichier '{filename}' introuvable")
        print(f"  Assurez-vous d'avoir transféré le fichier depuis Machine A")
        sys.exit(1)
    except ValueError as e:
        print(f"✗ Erreur : Format de clé invalide dans '{filename}' : {e}")
        print(f"  La clé doit être en format hexadécimal")
        sys.exit(1)
    except Exception as e:
        print(f"✗ Erreur lors de la lecture de la clé : {e}")
        sys.exit(1)


def decrypt_file(encrypted_data, key):
    """
    Déchiffre des données avec AES-256 en mode CBC.
    
    Args:
        encrypted_data (bytes): Données chiffrées (IV + ciphertext)
        key (bytes): Clé de déchiffrement (32 bytes)
    
    Returns:
        bytes: Données déchiffrées
    """
    try:
        # Extraire l'IV (16 premiers bytes) et le ciphertext
        if len(encrypted_data) < 16:
            print("✗ Erreur : Données chiffrées invalides (trop courtes)")
            sys.exit(1)
        
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Créer le cipher AES-256-CBC
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        # Déchiffrer
        plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Retirer le padding PKCS7
        pad_length = plaintext_padded[-1]
        if pad_length > 16 or pad_length == 0:
            print("✗ Erreur : Padding invalide lors du déchiffrement")
            sys.exit(1)
        
        plaintext = plaintext_padded[:-pad_length]
        
        print(f"✓ Fichier déchiffré : {len(plaintext)} bytes")
        return plaintext
        
    except Exception as e:
        print(f"✗ Erreur lors du déchiffrement : {e}")
        print("  Vérifiez que la clé est correcte")
        sys.exit(1)


def get_from_ipfs(cid, ipfs_address=IPFS_ADDRESS):
    """
    Récupère des données depuis IPFS en utilisant un CID.
    
    Args:
        cid (str): Content Identifier du fichier
        ipfs_address (str): Adresse du démon IPFS
    
    Returns:
        bytes: Données récupérées
    """
    try:
        print(f"Connexion au démon IPFS à {ipfs_address}...")
        client = ipfshttpclient.connect(ipfs_address)
        
        print(f"Récupération du fichier depuis IPFS (CID: {cid})...")
        data = client.cat(cid)
        
        print(f"✓ Fichier récupéré : {len(data)} bytes")
        return data
        
    except ipfshttpclient.exceptions.ConnectionError:
        print(f"✗ Erreur : Impossible de se connecter au démon IPFS à {ipfs_address}")
        print("  Vérifiez que le démon IPFS est lancé : ipfs daemon")
        sys.exit(1)
    except ipfshttpclient.exceptions.ErrorResponse as e:
        print(f"✗ Erreur IPFS : {e}")
        print(f"  Vérifiez que le CID '{cid}' est correct et que le fichier est disponible")
        sys.exit(1)
    except Exception as e:
        print(f"✗ Erreur lors de la récupération depuis IPFS : {e}")
        sys.exit(1)


def save_file(data, filename=OUTPUT_FILE):
    """
    Sauvegarde des données dans un fichier.
    
    Args:
        data (bytes): Données à sauvegarder
        filename (str): Nom du fichier de sortie
    """
    try:
        # Si le fichier existe déjà, demander confirmation (ou utiliser un nom différent)
        if os.path.exists(filename):
            base, ext = os.path.splitext(filename)
            counter = 1
            while os.path.exists(f"{base}_{counter}{ext}"):
                counter += 1
            filename = f"{base}_{counter}{ext}"
            print(f"⚠ Fichier existant, sauvegarde sous '{filename}'")
        
        with open(filename, 'wb') as f:
            f.write(data)
        print(f"✓ Fichier sauvegardé sous '{filename}'")
        return filename
        
    except Exception as e:
        print(f"✗ Erreur lors de la sauvegarde : {e}")
        sys.exit(1)


def calculate_sha256(data):
    """
    Calcule le hash SHA256 de données en mémoire.
    
    Args:
        data (bytes): Données à hasher
    
    Returns:
        str: Hash SHA256 en hexadécimal
    """
    return hashlib.sha256(data).hexdigest()


def main():
    """
    Fonction principale : orchestre la récupération, le déchiffrement et la vérification.
    """
    print("=" * 60)
    print("MACHINE B - Récupération de fichier chiffré depuis IPFS")
    print("=" * 60)
    print()
    
    # Demander le CID à l'utilisateur
    if len(sys.argv) > 1:
        cid = sys.argv[1]
    else:
        cid = input("Entrez le CID du fichier à récupérer : ").strip()
    
    if not cid:
        print("✗ Erreur : CID vide")
        sys.exit(1)
    
    print(f"CID reçu : {cid}")
    print()
    
    # Étape 1 : Lire la clé de chiffrement
    print("Étape 1 : Lecture de la clé de chiffrement...")
    key = read_key()
    print()
    
    # Étape 2 : Récupérer le fichier depuis IPFS
    print("Étape 2 : Récupération du fichier depuis IPFS...")
    encrypted_data = get_from_ipfs(cid)
    print()
    
    # Étape 3 : Déchiffrer le fichier
    print("Étape 3 : Déchiffrement du fichier...")
    decrypted_data = decrypt_file(encrypted_data, key)
    print()
    
    # Étape 4 : Sauvegarder le fichier déchiffré
    print("Étape 4 : Sauvegarde du fichier déchiffré...")
    output_filename = save_file(decrypted_data)
    print()
    
    # Étape 5 : Vérification d'intégrité (hash SHA256)
    print("Étape 5 : Vérification d'intégrité (SHA256)...")
    received_hash = calculate_sha256(decrypted_data)
    print(f"✓ Hash SHA256 du fichier reçu : {received_hash}")
    
    # Demander le hash original pour comparaison (optionnel)
    print()
    original_hash_input = input("Entrez le hash SHA256 original pour vérification (ou appuyez sur Entrée pour ignorer) : ").strip()
    
    if original_hash_input:
        if original_hash_input.lower() == received_hash.lower():
            print("✓✓✓ VÉRIFICATION RÉUSSIE : Les hashs correspondent !")
        else:
            print("✗✗✗ ERREUR : Les hashs ne correspondent pas !")
            print(f"  Hash original attendu : {original_hash_input}")
            print(f"  Hash reçu calculé     : {received_hash}")
    else:
        print("⚠ Vérification d'intégrité ignorée (hash original non fourni)")
    
    print()
    
    # Résumé final
    print("=" * 60)
    print("RÉSUMÉ")
    print("=" * 60)
    print(f"CID IPFS             : {cid}")
    print(f"Fichier reçu         : {output_filename}")
    print(f"Hash SHA256          : {received_hash}")
    print("=" * 60)


if __name__ == "__main__":
    main()

