import socket
import os
import hashlib
from cryptography.fernet import Fernet
import json
import threading
import time
import base64

CHUNK_SIZE = 1024 * 1024  # 1 MB chunks
BUFFER_SIZE = 4096

# Clé de chiffrement partagée (même pour tous les nœuds)
SHARED_KEY = base64.urlsafe_b64encode(b'shared_secret_key_32_bytes___!!!').ljust(44, b'=')

class P2PFileTransfer:
    def __init__(self, port: int = 5000):
        self.port = port
        self.cipher = Fernet(SHARED_KEY)
        self.server_socket = None
        self.running = False
    
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
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', self.port))
            self.server_socket.listen(5)
            self.server_socket.settimeout(1)
            self.running = True
            print(f"✓ Serveur P2P démarré sur le port {self.port}")
            
            while self.running:
                try:
                    client_socket, address = self.server_socket.accept()
                    print(f"→ Connexion reçue de {address[0]}:{address[1]}")
                    thread = threading.Thread(target=self.handle_incoming, args=(client_socket, address))
                    thread.daemon = True
                    thread.start()
                except socket.timeout:
                    continue
                except Exception as e:
                    if self.running:
                        print(f"Erreur acceptation: {e}")
        except OSError as e:
            print(f"✗ Impossible de démarrer le serveur: {e}")
            print(f"  Le port {self.port} est peut-être déjà utilisé")
        except Exception as e:
            print(f"✗ Erreur serveur: {e}")
        finally:
            self.cleanup()
    
    def handle_incoming(self, client_socket, address):
        """Gérer une connexion entrante"""
        try:
            client_socket.settimeout(30)
            
            # Recevoir les métadonnées du fichier
            metadata_json = b''
            while len(metadata_json) < 2048 and b'\n[END_METADATA]\n' not in metadata_json:
                try:
                    chunk = client_socket.recv(BUFFER_SIZE)
                    if not chunk:
                        break
                    metadata_json += chunk
                except socket.timeout:
                    print("Timeout réception métadonnées")
                    return
            
            metadata_str = metadata_json.decode().split('\n[END_METADATA]\n')[0]
            metadata = json.loads(metadata_str)
            
            filename = metadata['filename']
            file_size = metadata['file_size']
            original_hash = metadata['hash']
            
            print(f"  Fichier: {filename} ({file_size / 1024 / 1024:.2f} MB)")
            
            # Recevoir et déchiffrer le fichier
            received_size = 0
            sha256 = hashlib.sha256()
            
            with open(filename, 'wb') as f:
                while received_size < file_size:
                    try:
                        to_read = min(CHUNK_SIZE, file_size - received_size)
                        chunk_encrypted = client_socket.recv(to_read)
                        if not chunk_encrypted:
                            break
                        
                        chunk_decrypted = self.dechiffrer_chunk(chunk_encrypted)
                        f.write(chunk_decrypted)
                        sha256.update(chunk_decrypted)
                        received_size += len(chunk_decrypted)
                        
                        progress = (received_size / file_size) * 100
                        print(f"  Réception: {progress:.1f}%", end='\r')
                    except Exception as e:
                        print(f"\n  Erreur déchiffrement: {e}")
                        break
            
            received_hash = sha256.hexdigest()
            
            if received_hash == original_hash:
                print(f"\n✓ Fichier reçu et vérifié!")
                try:
                    client_socket.send(b'OK')
                except:
                    pass
            else:
                print(f"\n✗ Erreur: Hash ne correspond pas!")
                try:
                    client_socket.send(b'ERROR')
                except:
                    pass
                os.remove(filename)
        
        except Exception as e:
            print(f"✗ Erreur réception: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def envoyer_fichier(self, filepath: str, host: str, port: int):
        """Envoyer un fichier à un autre pair"""
        if not os.path.exists(filepath):
            print(f"✗ Fichier non trouvé: {filepath}")
            return
        
        client_socket = None
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
            client_socket.settimeout(10)
            client_socket.connect((host, port))
            print(f"→ Connecté à {host}:{port}")
            
            # Envoyer les métadonnées
            metadata_json = json.dumps(metadata) + '\n[END_METADATA]\n'
            client_socket.send(metadata_json.encode())
            
            print(f"  Fichier: {filename} ({file_size / 1024 / 1024:.2f} MB)")
            
            # Envoyer le fichier chiffré par chunks
            sent_size = 0
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    chunk_encrypted = self.chiffrer_chunk(chunk)
                    client_socket.sendall(chunk_encrypted)
                    sent_size += len(chunk)
                    
                    progress = (sent_size / file_size) * 100
                    print(f"  Envoi: {progress:.1f}%", end='\r')
            
            print(f"\n✓ Fichier envoyé!")
            
            # Attendre la confirmation
            try:
                client_socket.settimeout(5)
                response = client_socket.recv(1024)
                if response == b'OK':
                    print("✓ Confirmé par le destinataire!")
                elif response == b'ERROR':
                    print("✗ Erreur côté destinataire")
            except socket.timeout:
                print("⚠ Pas de confirmation reçue")
        
        except ConnectionRefusedError:
            print(f"✗ Impossible de se connecter à {host}:{port}")
            print("  Vérifiez l'adresse IP et le port")
        except Exception as e:
            print(f"✗ Erreur d'envoi: {e}")
        finally:
            if client_socket:
                try:
                    client_socket.close()
                except:
                    pass
    
    def cleanup(self):
        """Nettoyer les ressources"""
        self.running = False
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
    
    def arreter(self):
        """Arrêter le serveur"""
        self.cleanup()


class P2PNode:
    def __init__(self, port: int = 5000):
        self.transfer = P2PFileTransfer(port)
        self.port = port
        self.server_thread = None
    
    def start(self):
        """Démarrer le nœud P2P (serveur en arrière-plan)"""
        self.server_thread = threading.Thread(target=self.transfer.start_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        time.sleep(0.5)
    
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
            print("Nœud P2P actif (Ctrl+C pour arrêter)")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n✓ Arrêt du nœud...")
                node.stop()
        
        elif mode == "send" and len(sys.argv) > 4:
            # Envoyer un fichier
            filepath = sys.argv[2]
            host = sys.argv[3]
            port = int(sys.argv[4])
            
            node = P2PNode()
            node.start()
            time.sleep(0.5)
            node.send(filepath, host, port)
        
        else:
            print("Usage:")
            print("  Serveur: python server.py server [port]")
            print("  Envoi:   python server.py send <fichier> <hôte> <port>")
    else:
        print("Usage:")
        print("  Serveur: python server.py server [port]")
        print("  Envoi:   python server.py send <fichier> <hôte> <port>")