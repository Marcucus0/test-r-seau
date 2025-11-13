#!/usr/bin/env python3
"""
Système P2P sécurisé pour échanger des fichiers chiffrés en chunks
entre deux machines sur le même réseau local.

Fonctionnalités :
- Découpage de fichiers en chunks chiffrés (AES-256)
- Vérification d'intégrité avec SHA256
- Communication sécurisée via HTTPS avec mTLS
- API FastAPI pour l'échange de chunks
- Client P2P pour envoyer/télécharger des fichiers complets
"""

import json
import hashlib
from pathlib import Path
from typing import Optional, Dict, List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import secrets
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import httpx
import ssl
import asyncio
from datetime import datetime
from hypercorn.config import Config as HypercornConfig
from hypercorn.asyncio import serve as hypercorn_serve

# ============================================================================
# CONFIGURATION
# ============================================================================

# Taille des chunks en octets (1 Mo par défaut)
CHUNK_SIZE = 1024 * 1024  # 1 Mo

# Dossiers de stockage
CHUNKS_DIR = Path("chunks")
RECEIVED_DIR = Path("received")
CERTS_DIR = Path("certs")

# Chemins des certificats (à générer avec generate_certs.py)
CA_CERT = CERTS_DIR / "ca-cert.pem"
SERVER_CERT = CERTS_DIR / "server-cert.pem"
SERVER_KEY = CERTS_DIR / "server-key.pem"
CLIENT_CERT = CERTS_DIR / "client-cert.pem"
CLIENT_KEY = CERTS_DIR / "client-key.pem"

# Port par défaut
DEFAULT_PORT = 8443

# ============================================================================
# INITIALISATION DES DOSSIERS
# ============================================================================

def init_directories():
    """Crée les dossiers nécessaires s'ils n'existent pas."""
    CHUNKS_DIR.mkdir(exist_ok=True)
    RECEIVED_DIR.mkdir(exist_ok=True)
    CERTS_DIR.mkdir(exist_ok=True)

# ============================================================================
# GESTION DU CHIFFREMENT AES-256
# ============================================================================

class EncryptionManager:
    """
    Gère le chiffrement/déchiffrement des chunks avec AES-256 en mode GCM.
    AES-256-GCM fournit à la fois le chiffrement et l'authentification.
    """
    
    def __init__(self, password: Optional[bytes] = None):
        """
        Initialise le gestionnaire de chiffrement.
        
        Args:
            password: Mot de passe pour dériver la clé. Si None, génère une clé aléatoire.
        """
        if password is None:
            # Génère une clé aléatoire de 32 octets (256 bits) pour AES-256
            self.key = secrets.token_bytes(32)
        else:
            # Dérive une clé de 32 octets (256 bits) à partir du mot de passe
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,  # 32 octets = 256 bits pour AES-256
                salt=b'p2p_file_exchange_salt',  # Salt fixe pour la démo
                iterations=100000,
                backend=default_backend()
            )
            self.key = kdf.derive(password)
        
        # Initialise AES-256-GCM avec la clé
        self.cipher = AESGCM(self.key)
        # Nonce de 12 octets (96 bits) pour GCM (généré à chaque chiffrement)
        self.nonce_size = 12
    
    def encrypt_chunk(self, data: bytes) -> bytes:
        """
        Chiffre un chunk de données avec AES-256-GCM.
        
        Format: nonce (12 octets) + données chiffrées + tag d'authentification (16 octets)
        
        Args:
            data: Données brutes à chiffrer
            
        Returns:
            Données chiffrées avec nonce et tag (format: nonce + ciphertext + tag)
        """
        # Génère un nonce aléatoire pour ce chunk
        nonce = secrets.token_bytes(self.nonce_size)
        
        # Chiffre les données (GCM ajoute automatiquement le tag d'authentification)
        ciphertext = self.cipher.encrypt(nonce, data, None)
        
        # Combine nonce + ciphertext (qui contient déjà le tag)
        return nonce + ciphertext
    
    def decrypt_chunk(self, encrypted_data: bytes) -> bytes:
        """
        Déchiffre un chunk de données avec AES-256-GCM.
        
        Args:
            encrypted_data: Données chiffrées (format: nonce + ciphertext + tag)
            
        Returns:
            Données déchiffrées
            
        Raises:
            Exception: Si le déchiffrement échoue (données corrompues ou tag invalide)
        """
        try:
            # Extrait le nonce (12 premiers octets)
            nonce = encrypted_data[:self.nonce_size]
            # Le reste est le ciphertext avec le tag
            ciphertext = encrypted_data[self.nonce_size:]
            
            # Déchiffre (GCM vérifie automatiquement le tag d'authentification)
            return self.cipher.decrypt(nonce, ciphertext, None)
        except Exception as e:
            raise Exception(f"Échec du déchiffrement: {e}")

# ============================================================================
# GESTION DES CHUNKS
# ============================================================================

def calculate_hash(data: bytes) -> str:
    """
    Calcule le hash SHA256 d'un chunk.
    
    Args:
        data: Données du chunk
        
    Returns:
        Hash hexadécimal
    """
    return hashlib.sha256(data).hexdigest()

def save_chunk(chunk_hash: str, encrypted_data: bytes):
    """
    Sauvegarde un chunk chiffré sur le disque.
    
    Args:
        chunk_hash: Hash du chunk (nom du fichier)
        encrypted_data: Données chiffrées à sauvegarder
    """
    chunk_path = CHUNKS_DIR / chunk_hash
    chunk_path.write_bytes(encrypted_data)

def load_chunk(chunk_hash: str) -> Optional[bytes]:
    """
    Charge un chunk chiffré depuis le disque.
    
    Args:
        chunk_hash: Hash du chunk à charger
        
    Returns:
        Données chiffrées ou None si le chunk n'existe pas
    """
    chunk_path = CHUNKS_DIR / chunk_hash
    if chunk_path.exists():
        return chunk_path.read_bytes()
    return None

def list_chunks() -> List[str]:
    """
    Liste tous les chunks disponibles localement.
    
    Returns:
        Liste des hashes de chunks
    """
    return [f.name for f in CHUNKS_DIR.iterdir() if f.is_file()]

# ============================================================================
# DÉCOUPAGE ET RECONSTITUTION DE FICHIERS
# ============================================================================

def split_file_into_chunks(file_path: Path, encryption_manager: EncryptionManager) -> Dict[str, Dict]:
    """
    Découpe un fichier en chunks chiffrés.
    
    Args:
        file_path: Chemin du fichier à découper
        encryption_manager: Gestionnaire de chiffrement
        
    Returns:
        Dictionnaire avec les métadonnées du fichier et la liste des chunks
    """
    file_data = file_path.read_bytes()
    file_size = len(file_data)
    chunks_metadata = []
    
    # Découpage en chunks
    for i in range(0, file_size, CHUNK_SIZE):
        chunk_data = file_data[i:i + CHUNK_SIZE]
        
        # Chiffrement du chunk
        encrypted_chunk = encryption_manager.encrypt_chunk(chunk_data)
        
        # Calcul du hash du chunk chiffré (pour l'identification)
        chunk_hash = calculate_hash(encrypted_chunk)
        
        # Sauvegarde locale
        save_chunk(chunk_hash, encrypted_chunk)
        
        chunks_metadata.append({
            "hash": chunk_hash,
            "size": len(encrypted_chunk),
            "index": i // CHUNK_SIZE
        })
    
    return {
        "filename": file_path.name,
        "original_size": file_size,
        "chunks": chunks_metadata,
        "total_chunks": len(chunks_metadata)
    }

def reconstruct_file_from_chunks(
    chunks_metadata: Dict,
    encryption_manager: EncryptionManager,
    output_path: Path
) -> bool:
    """
    Reconstitue un fichier à partir de ses chunks déchiffrés.
    
    Args:
        chunks_metadata: Métadonnées du fichier (avec liste des chunks)
        encryption_manager: Gestionnaire de déchiffrement
        output_path: Chemin de sortie pour le fichier reconstitué
        
    Returns:
        True si succès, False sinon
    """
    try:
        # Trie les chunks par index
        sorted_chunks = sorted(chunks_metadata["chunks"], key=lambda x: x["index"])
        
        file_data = b""
        
        for chunk_info in sorted_chunks:
            chunk_hash = chunk_info["hash"]
            
            # Charge le chunk localement
            encrypted_chunk = load_chunk(chunk_hash)
            if encrypted_chunk is None:
                print(f"ERREUR: Chunk {chunk_hash} introuvable localement")
                return False
            
            # Vérifie le hash
            if calculate_hash(encrypted_chunk) != chunk_hash:
                print(f"ERREUR: Hash invalide pour le chunk {chunk_hash}")
                return False
            
            # Déchiffre le chunk
            try:
                decrypted_chunk = encryption_manager.decrypt_chunk(encrypted_chunk)
                file_data += decrypted_chunk
            except Exception as e:
                print(f"ERREUR: Échec du déchiffrement du chunk {chunk_hash}: {e}")
                return False
        
        # Vérifie la taille finale
        if len(file_data) != chunks_metadata["original_size"]:
            print(f"ERREUR: Taille incorrecte. Attendu: {chunks_metadata['original_size']}, Obtenu: {len(file_data)}")
            return False
        
        # Sauvegarde le fichier reconstitué
        output_path.write_bytes(file_data)
        print(f"✓ Fichier reconstitué: {output_path}")
        return True
        
    except Exception as e:
        print(f"ERREUR lors de la reconstitution: {e}")
        return False

# ============================================================================
# API FASTAPI
# ============================================================================

app = FastAPI(title="P2P File Exchange", description="API pour échanger des chunks chiffrés")

class ChunkUpload(BaseModel):
    """Modèle pour l'upload d'un chunk."""
    hash: str
    data: str  # Base64 encoded

@app.post("/upload_chunk")
async def upload_chunk(chunk: ChunkUpload):
    """
    Endpoint pour recevoir un chunk chiffré.
    
    Le chunk est reçu en base64, décodé, puis sauvegardé localement.
    """
    try:
        # Décode le chunk depuis base64
        encrypted_data = base64.b64decode(chunk.data)
        
        # Vérifie le hash
        calculated_hash = calculate_hash(encrypted_data)
        if calculated_hash != chunk.hash:
            raise HTTPException(
                status_code=400,
                detail=f"Hash invalide. Attendu: {chunk.hash}, Calculé: {calculated_hash}"
            )
        
        # Sauvegarde le chunk
        save_chunk(chunk.hash, encrypted_data)
        
        return {
            "status": "success",
            "message": f"Chunk {chunk.hash} reçu et sauvegardé",
            "hash": chunk.hash
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur lors de l'upload: {str(e)}")

@app.get("/download_chunk/{chunk_hash}")
async def download_chunk(chunk_hash: str):
    """
    Endpoint pour récupérer un chunk spécifique par son hash.
    
    Retourne le chunk chiffré encodé en base64.
    """
    encrypted_data = load_chunk(chunk_hash)
    
    if encrypted_data is None:
        raise HTTPException(status_code=404, detail=f"Chunk {chunk_hash} introuvable")
    
    # Encode en base64 pour le transport
    data_b64 = base64.b64encode(encrypted_data).decode('utf-8')
    
    return {
        "hash": chunk_hash,
        "data": data_b64,
        "size": len(encrypted_data)
    }

@app.get("/list_chunks")
async def list_chunks_endpoint():
    """
    Endpoint pour lister tous les chunks disponibles localement.
    """
    chunks = list_chunks()
    return {
        "chunks": chunks,
        "count": len(chunks)
    }

@app.get("/health")
async def health_check():
    """Endpoint de santé pour vérifier que le serveur fonctionne."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "chunks_count": len(list_chunks())
    }

# ============================================================================
# CLIENT P2P
# ============================================================================

class P2PClient:
    """
    Client P2P pour envoyer et télécharger des fichiers complets.
    """
    
    def __init__(self, peer_address: str, peer_port: int = DEFAULT_PORT):
        """
        Initialise le client P2P.
        
        Args:
            peer_address: Adresse IP du pair
            peer_port: Port du pair
        """
        self.peer_address = peer_address
        self.peer_port = peer_port
        self.base_url = f"https://{peer_address}:{peer_port}"
        
        # Configuration SSL pour mTLS avec httpx
        # httpx utilise verify pour le certificat CA et cert pour le certificat client
        # Vérifie que les fichiers existent
        if not CA_CERT.exists() or not CLIENT_CERT.exists() or not CLIENT_KEY.exists():
            raise FileNotFoundError("Certificats manquants pour le client P2P")
        
        self.verify = str(CA_CERT)  # Certificat CA pour vérifier le serveur
        self.cert = (str(CLIENT_CERT), str(CLIENT_KEY))  # Certificat client pour mTLS
    
    async def upload_chunk_to_peer(self, chunk_hash: str, encrypted_data: bytes) -> bool:
        """
        Envoie un chunk chiffré au pair.
        
        Args:
            chunk_hash: Hash du chunk
            encrypted_data: Données chiffrées
            
        Returns:
            True si succès, False sinon
        """
        try:
            # Encode en base64
            data_b64 = base64.b64encode(encrypted_data).decode('utf-8')
            
            async with httpx.AsyncClient(verify=self.verify, cert=self.cert) as client:
                response = await client.post(
                    f"{self.base_url}/upload_chunk",
                    json={"hash": chunk_hash, "data": data_b64},
                    timeout=30.0
                )
                response.raise_for_status()
                return True
        except Exception as e:
            print(f"ERREUR lors de l'upload du chunk {chunk_hash}: {e}")
            return False
    
    async def download_chunk_from_peer(self, chunk_hash: str) -> Optional[bytes]:
        """
        Télécharge un chunk chiffré depuis le pair.
        
        Args:
            chunk_hash: Hash du chunk à télécharger
            
        Returns:
            Données chiffrées ou None si échec
        """
        try:
            async with httpx.AsyncClient(verify=self.verify, cert=self.cert) as client:
                response = await client.get(
                    f"{self.base_url}/download_chunk/{chunk_hash}",
                    timeout=30.0
                )
                response.raise_for_status()
                data = response.json()
                
                # Décode depuis base64
                encrypted_data = base64.b64decode(data["data"])
                
                # Vérifie le hash
                if calculate_hash(encrypted_data) != chunk_hash:
                    print(f"ERREUR: Hash invalide pour le chunk téléchargé {chunk_hash}")
                    return None
                
                return encrypted_data
        except Exception as e:
            print(f"ERREUR lors du téléchargement du chunk {chunk_hash}: {e}")
            return None
    
    async def list_peer_chunks(self) -> List[str]:
        """
        Liste les chunks disponibles sur le pair.
        
        Returns:
            Liste des hashes de chunks
        """
        try:
            async with httpx.AsyncClient(verify=self.verify, cert=self.cert) as client:
                response = await client.get(
                    f"{self.base_url}/list_chunks",
                    timeout=10.0
                )
                response.raise_for_status()
                data = response.json()
                return data.get("chunks", [])
        except Exception as e:
            print(f"ERREUR lors de la liste des chunks: {e}")
            return []
    
    async def send_file(self, file_path: Path, encryption_manager: EncryptionManager) -> bool:
        """
        Envoie un fichier complet au pair (découpe + chiffrement + upload).
        
        Args:
            file_path: Chemin du fichier à envoyer
            encryption_manager: Gestionnaire de chiffrement
            
        Returns:
            True si succès, False sinon
        """
        if not file_path.exists():
            print(f"ERREUR: Fichier introuvable: {file_path}")
            return False
        
        print(f"📤 Envoi du fichier: {file_path.name}")
        
        # Découpe le fichier en chunks
        print("  → Découpage en chunks...")
        metadata = split_file_into_chunks(file_path, encryption_manager)
        
        # Envoie chaque chunk au pair
        print(f"  → Envoi de {metadata['total_chunks']} chunks...")
        success_count = 0
        
        for chunk_info in metadata["chunks"]:
            chunk_hash = chunk_info["hash"]
            encrypted_chunk = load_chunk(chunk_hash)
            
            if await self.upload_chunk_to_peer(chunk_hash, encrypted_chunk):
                success_count += 1
                print(f"    ✓ Chunk {chunk_info['index'] + 1}/{metadata['total_chunks']} envoyé")
            else:
                print(f"    ✗ Échec du chunk {chunk_info['index'] + 1}/{metadata['total_chunks']}")
        
        if success_count == metadata["total_chunks"]:
            print(f"✓ Fichier envoyé avec succès ({success_count} chunks)")
            
            # Sauvegarde les métadonnées pour faciliter le téléchargement ultérieur
            metadata_file = RECEIVED_DIR / f"{file_path.stem}_metadata.json"
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f, indent=2)
            print(f"  → Métadonnées sauvegardées: {metadata_file}")
            
            return True
        else:
            print(f"✗ Échec partiel: {success_count}/{metadata['total_chunks']} chunks envoyés")
            return False
    
    async def download_file(
        self,
        chunks_metadata: Dict,
        encryption_manager: EncryptionManager,
        output_filename: Optional[str] = None
    ) -> bool:
        """
        Télécharge un fichier complet depuis le pair (download + vérification + déchiffrement).
        
        Args:
            chunks_metadata: Métadonnées du fichier avec liste des chunks
            encryption_manager: Gestionnaire de déchiffrement
            output_filename: Nom du fichier de sortie (optionnel)
            
        Returns:
            True si succès, False sinon
        """
        filename = output_filename or chunks_metadata.get("filename", "downloaded_file")
        output_path = RECEIVED_DIR / filename
        
        print(f"📥 Téléchargement du fichier: {filename}")
        print(f"  → {chunks_metadata['total_chunks']} chunks à télécharger...")
        
        # Télécharge chaque chunk
        for chunk_info in chunks_metadata["chunks"]:
            chunk_hash = chunk_info["hash"]
            
            # Vérifie d'abord si le chunk existe localement
            if load_chunk(chunk_hash) is None:
                print(f"  → Téléchargement du chunk {chunk_info['index'] + 1}/{chunks_metadata['total_chunks']}...")
                encrypted_chunk = await self.download_chunk_from_peer(chunk_hash)
                
                if encrypted_chunk is None:
                    print(f"    ✗ Échec du téléchargement du chunk {chunk_info['index'] + 1}")
                    return False
                
                # Sauvegarde le chunk localement
                save_chunk(chunk_hash, encrypted_chunk)
                print(f"    ✓ Chunk {chunk_info['index'] + 1}/{chunks_metadata['total_chunks']} téléchargé")
            else:
                print(f"    ⊙ Chunk {chunk_info['index'] + 1}/{chunks_metadata['total_chunks']} déjà présent localement")
        
        # Reconstitue le fichier
        print("  → Reconstitution du fichier...")
        if reconstruct_file_from_chunks(chunks_metadata, encryption_manager, output_path):
            print(f"✓ Fichier téléchargé et reconstitué: {output_path}")
            return True
        else:
            print(f"✗ Échec de la reconstitution du fichier")
            return False

# ============================================================================
# INTERFACE UTILISATEUR
# ============================================================================

def print_menu():
    """Affiche le menu principal."""
    print("\n" + "="*60)
    print("  SYSTÈME P2P D'ÉCHANGE DE FICHIERS CHIFFRÉS")
    print("="*60)
    print("1. Envoyer un fichier à un pair")
    print("2. Télécharger un fichier depuis un pair")
    print("3. Lister les chunks locaux")
    print("4. Lister les chunks du pair")
    print("5. Quitter")
    print("="*60)

async def main():
    """Fonction principale avec interface interactive."""
    init_directories()
    
    # Vérifie que les certificats existent
    if not all([CA_CERT.exists(), SERVER_CERT.exists(), SERVER_KEY.exists(), 
                CLIENT_CERT.exists(), CLIENT_KEY.exists()]):
        print("⚠️  ERREUR: Certificats manquants!")
        print(f"   Veuillez exécuter: python generate_certs.py")
        return
    
    # Configuration du serveur
    print("\n🔧 Configuration du serveur")
    port = input(f"Port du serveur [{DEFAULT_PORT}]: ").strip()
    port = int(port) if port else DEFAULT_PORT
    
    # Configuration du pair
    print("\n🔧 Configuration du pair")
    peer_address = input("Adresse IP du pair (ex: 192.168.1.100): ").strip()
    if not peer_address:
        print("⚠️  Aucune adresse de pair configurée. Mode serveur uniquement.")
        peer_address = None
    else:
        peer_port_input = input(f"Port du pair [{DEFAULT_PORT}]: ").strip()
        peer_port = int(peer_port_input) if peer_port_input else DEFAULT_PORT
    
    # Initialise le gestionnaire de chiffrement
    # Pour cette démo, on utilise une clé partagée (en production, utiliser un échange de clés)
    print("\n🔐 Configuration du chiffrement")
    print("   Note: Les deux machines doivent utiliser la même clé de chiffrement")
    password = input("Mot de passe pour le chiffrement (ou Entrée pour clé aléatoire): ").strip()
    password_bytes = password.encode() if password else None
    encryption_manager = EncryptionManager(password_bytes)
    
    # Démarre le serveur en arrière-plan
    print(f"\n🚀 Démarrage du serveur sur le port {port}...")
    
    # Configuration SSL pour mTLS (authentification mutuelle)
    # Utilise hypercorn qui supporte mieux mTLS que uvicorn
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(str(SERVER_CERT), str(SERVER_KEY))
    ssl_context.load_verify_locations(str(CA_CERT))
    ssl_context.verify_mode = ssl.CERT_REQUIRED  # Exige un certificat client valide
    
    # Configuration hypercorn pour mTLS
    # Hypercorn accepte ssl_context directement dans les versions récentes
    hypercorn_config = HypercornConfig()
    hypercorn_config.bind = [f"0.0.0.0:{port}"]
    
    # Vérifie si hypercorn supporte ssl_context
    if hasattr(hypercorn_config, 'ssl_context'):
        # Version récente de hypercorn qui supporte ssl_context
        hypercorn_config.ssl_context = ssl_context
    else:
        # Fallback: utilise keyfile et certfile
        # Note: Le mTLS strict nécessite ssl_context, mais on peut quand même utiliser SSL
        hypercorn_config.keyfile = str(SERVER_KEY)
        hypercorn_config.certfile = str(SERVER_CERT)
        print("⚠️  Attention: Version de hypercorn sans support ssl_context.")
        print("   Le serveur utilisera SSL mais le mTLS strict peut ne pas fonctionner.")
        print("   Mettez à jour hypercorn: pip install --upgrade hypercorn")
    
    hypercorn_config.loglevel = "WARNING"
    
    # Lance le serveur hypercorn dans une tâche asyncio
    async def run_server():
        try:
            await hypercorn_serve(app, hypercorn_config)
        except asyncio.CancelledError:
            pass
    
    server_task = asyncio.create_task(run_server())
    
    # Attend un peu pour que le serveur démarre
    await asyncio.sleep(2)
    print(f"✓ Serveur démarré sur https://0.0.0.0:{port}")
    
    # Initialise le client si un pair est configuré
    client = None
    if peer_address:
        client = P2PClient(peer_address, peer_port)
        print(f"✓ Client P2P configuré pour {peer_address}:{peer_port}")
    
    # Boucle principale
    while True:
        print_menu()
        choice = input("\nChoix: ").strip()
        
        if choice == "1":
            # Envoyer un fichier
            if not client:
                print("⚠️  Aucun pair configuré!")
                continue
            
            file_path_input = input("Chemin du fichier à envoyer: ").strip()
            file_path = Path(file_path_input)
            
            if not file_path.exists():
                print(f"⚠️  Fichier introuvable: {file_path}")
                continue
            
            await client.send_file(file_path, encryption_manager)
        
        elif choice == "2":
            # Télécharger un fichier
            if not client:
                print("⚠️  Aucun pair configuré!")
                continue
            
            print("\nPour télécharger un fichier, vous devez fournir les métadonnées du fichier.")
            
            # Liste les fichiers de métadonnées disponibles
            metadata_files = list(RECEIVED_DIR.glob("*_metadata.json"))
            if metadata_files:
                print("\n📋 Fichiers de métadonnées disponibles:")
                for i, meta_file in enumerate(metadata_files, 1):
                    try:
                        with open(meta_file, 'r') as f:
                            meta_data = json.load(f)
                            filename = meta_data.get('filename', 'inconnu')
                            print(f"  {i}. {meta_file.name} → {filename}")
                    except:
                        print(f"  {i}. {meta_file.name}")
                print(f"  {len(metadata_files) + 1}. Saisie manuelle")
            
            metadata_input = input("\nNuméro du fichier de métadonnées ou chemin (ou Entrée pour saisie manuelle): ").strip()
            
            if metadata_input:
                # Essaie d'abord comme numéro
                if metadata_input.isdigit() and metadata_files:
                    idx = int(metadata_input) - 1
                    if 0 <= idx < len(metadata_files):
                        metadata_path = metadata_files[idx]
                    else:
                        print("⚠️  Numéro invalide")
                        continue
                else:
                    # Sinon, traite comme un chemin
                    metadata_path = Path(metadata_input)
                
                if metadata_path.exists():
                    try:
                        with open(metadata_path, 'r', encoding='utf-8') as f:
                            metadata = json.load(f)
                    except Exception as e:
                        print(f"⚠️  Erreur lors de la lecture du fichier: {e}")
                        continue
                else:
                    print("⚠️  Fichier de métadonnées introuvable")
                    continue
            else:
                # Saisie manuelle (pour la démo)
                print("\nSaisie manuelle des métadonnées:")
                filename = input("Nom du fichier: ").strip()
                total_chunks = int(input("Nombre de chunks: ").strip())
                chunks = []
                for i in range(total_chunks):
                    chunk_hash = input(f"Hash du chunk {i+1}: ").strip()
                    chunks.append({"hash": chunk_hash, "index": i})
                
                metadata = {
                    "filename": filename,
                    "total_chunks": total_chunks,
                    "chunks": chunks,
                    "original_size": 0  # Inconnu
                }
            
            await client.download_file(metadata, encryption_manager)
        
        elif choice == "3":
            # Lister les chunks locaux
            chunks = list_chunks()
            print(f"\n📦 Chunks locaux ({len(chunks)}):")
            for chunk_hash in chunks[:20]:  # Limite à 20 pour l'affichage
                print(f"  - {chunk_hash}")
            if len(chunks) > 20:
                print(f"  ... et {len(chunks) - 20} autres")
        
        elif choice == "4":
            # Lister les chunks du pair
            if not client:
                print("⚠️  Aucun pair configuré!")
                continue
            
            print("\n📦 Récupération de la liste des chunks du pair...")
            chunks = await client.list_peer_chunks()
            print(f"Chunks disponibles sur le pair ({len(chunks)}):")
            for chunk_hash in chunks[:20]:
                print(f"  - {chunk_hash}")
            if len(chunks) > 20:
                print(f"  ... et {len(chunks) - 20} autres")
        
        elif choice == "5":
            # Quitter
            print("\n👋 Arrêt du serveur...")
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass
            break
        
        else:
            print("⚠️  Choix invalide!")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n\n👋 Arrêt du programme...")
    except Exception as e:
        print(f"\n❌ ERREUR: {e}")
        import traceback
        traceback.print_exc()

