import socket
import os
import hashlib
from cryptography.fernet import Fernet
import json
import threading
import time

CHUNK_SIZE = 1024 * 1024  # 1 MB chunks
BUFFER_SIZE = 4096

class P2PFileTransfer:
    def __init__(self, port: int = 5000):
        self.port = port
        self.cipher = Fernet(Fernet.generate_key())
        self.server_socket = None
        self.running = False
        self.peers = {}  # {address: socket}
    
    def chiffrer_chunk(self, data: bytes) -> bytes:
        """Chiffrer un chunk de données"""
        return self.cipher.encrypt(data)
    
    def dechiffrer_chunk(self, data: bytes) -> bytes:
        """Déchiffrer un chunk de données"""
        return self.cipher.decrypt(data)
    
    def calculer_hash(self, filepath: str) -> str:
        """Calculer le hash SHA256 du fichier"""
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def start_server(self):
        """Démarrer le serveur P2P"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind(('0.0.0.0', self.port))
        self.server_socket.listen(5)
        self.running = True
        print(f"Serveur P2P démarré sur le port {self.port}")
        
        try:
            while self.running:
                client_socket, address = self.server_socket.accept()
                print(f"Connexion reçue de {address[0]}:{address[1]}")
                thread = threading.Thread(target=self.handle_incoming, args=(client_socket, address))
                thread.daemon = True
                thread.start()
        except KeyboardInterrupt:
            print("\nServeur arrêté")
        finally:
            self.running = False
            self.server_socket.close()
    
    def handle_incoming(self, client_socket, address):
        """Gérer une connexion entrante"""
        try:
            # Recevoir les métadonnées du fichier
            metadata_json = b''
            while len(metadata_json) < 1024:
                chunk = client_socket.recv(BUFFER_SIZE)
                if not chunk:
                    break
                metadata_json += chunk
                if b'\n[END_METADATA]\n' in metadata_json:
                    break
            
            metadata_str = metadata_json.decode().split('\n[END_METADATA]\n')[0]
            metadata = json.loads(metadata_str)
            
            filename = metadata['filename']
            file_size = metadata['file_size']
            original_hash = metadata['hash']
            
            print(f"Réception du fichier: {filename} ({file_size} bytes) de {address[0]}")
            
            # Recevoir et déchiffrer le fichier
            received_size = 0
            sha256 = hashlib.sha256()
            
            with open(filename, 'wb') as f:
                while received_size < file_size:
                    chunk_encrypted = client_socket.recv(CHUNK_SIZE)
                    if not chunk_encrypted:
                        break
                    
                    try:
                        chunk_decrypted = self.dechiffrer_chunk(chunk_encrypted)
                        f.write(chunk_decrypted)
                        sha256.update(chunk_decrypted)
                        received_size += len(chunk_decrypted)
                        
                        progress = (received_size / file_size) * 100
                        print(f"Progression réception: {progress:.1f}%", end='\r')
                    except Exception as e:
                        print(f"Erreur déchiffrement: {e}")
                        break
            
            received_hash = sha256.hexdigest()
            
            if received_hash == original_hash:
                print(f"\n✓ Fichier reçu et vérifié avec succès!")
                client_socket.send(b'OK')
            else:
                print(f"\n✗ Erreur: Hash ne correspond pas!")
                client_socket.send(b'ERROR')
                os.remove(filename)
        
        except Exception as e:
            print(f"Erreur: {e}")
        finally:
            client_socket.close()
    
    def envoyer_fichier(self, filepath: str, host: str, port: int):
        """Envoyer un fichier à un autre pair"""
        if not os.path.exists(filepath):
            print(f"Fichier non trouvé: {filepath}")
            return
        
        try:
            # Préparer les métadonnées
            file_size = os.path.getsize(filepath)
            file_hash = self.calculer_hash(filepath)
            filename = os.path.basename(filepath)
            
            metadata = {
                'filename': filename,
                'file_size': file_size,
                'hash': file_hash
            }
            
            # Connecter au pair
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect((host, port))
            print(f"Connecté à {host}:{port}")
            
            # Envoyer les métadonnées
            metadata_json = json.dumps(metadata) + '\n[END_METADATA]\n'
            client_socket.send(metadata_json.encode())
            
            print(f"Envoi du fichier: {filename} ({file_size} bytes)")
            
            # Envoyer le fichier chiffré par chunks
            sent_size = 0
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    chunk_encrypted = self.chiffrer_chunk(chunk)
                    client_socket.send(chunk_encrypted)
                    sent_size += len(chunk)
                    
                    progress = (sent_size / file_size) * 100
                    print(f"Progression envoi: {progress:.1f}%", end='\r')
            
            # Attendre la confirmation
            response = client_socket.recv(1024)
            if response == b'OK':
                print(f"\n✓ Fichier envoyé et confirmé!")
            else:
                print(f"\n✗ Erreur de transfert")
            
            client_socket.close()
        
        except Exception as e:
            print(f"Erreur d'envoi: {e}")
    
    def arreter(self):
        """Arrêter le serveur"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()


class P2PNode:
    def __init__(self, port: int = 5000):
        self.transfer = P2PFileTransfer(port)
        self.port = port
    
    def start(self):
        """Démarrer le nœud P2P (serveur en arrière-plan)"""
        server_thread = threading.Thread(target=self.transfer.start_server)
        server_thread.daemon = True
        server_thread.start()
        time.sleep(1)  # Laisser le serveur démarrer
    
    def send(self, filepath: str, host: str, port: int):
        """Envoyer un fichier"""
        self.transfer.envoyer_fichier(filepath, host, port)
    
    def stop(self):
        """Arrêter le nœud"""
        self.transfer.arreter()


# Exemple d'utilisation
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        mode = sys.argv[1]
        
        if mode == "server":
            # Démarrer comme nœud P2P
            port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
            node = P2PNode(port)
            node.start()
            print(f"Nœud P2P actif sur le port {port}")
            print("Appuyez sur Ctrl+C pour arrêter")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nArrêt du nœud...")
                node.stop()
        
        elif mode == "send" and len(sys.argv) > 4:
            # Envoyer un fichier
            filepath = sys.argv[2]
            host = sys.argv[3]
            port = int(sys.argv[4])
            
            node = P2PNode()
            node.start()
            node.send(filepath, host, port)
        
        else:
            print("Usage:")
            print("  Serveur: python script.py server [port]")
            print("  Envoi:   python script.py send <fichier> <hôte> <port>")
    else:
        print("Usage:")
        print("  Serveur: python script.py server [port]")
        print("  Envoi:   python script.py send <fichier> <hôte> <port>")