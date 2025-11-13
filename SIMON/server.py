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

class P2PFileTransfer:
    def __init__(self, port: int = 5000):
        self.port = port
        self.server_socket = None
        self.running = False
        self.fichiers_disponibles = {}  # {filename: {hash, size, is_encrypted}}
    
    def chiffrer_chunk(self, data: bytes, key: Fernet) -> bytes:
        """Chiffrer un chunk de données avec une clé"""
        return key.encrypt(data)
    
    def dechiffrer_chunk(self, data: bytes, key: Fernet) -> bytes:
        """Déchiffrer un chunk de données avec une clé"""
        return key.decrypt(data)
    
    def creer_cle_depuis_mdp(self, password: str) -> Fernet:
        """Créer une clé Fernet valide à partir d'un mot de passe"""
        hashed = hashlib.sha256(password.encode()).digest()
        key = base64.urlsafe_b64encode(hashed)
        return Fernet(key)
    
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
                    thread = threading.Thread(target=self.handle_client, args=(client_socket, address))
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
    
    def handle_client(self, client_socket, address):
        """Gérer une connexion client"""
        try:
            client_socket.settimeout(30)
            
            # Recevoir la commande
            commande_data = client_socket.recv(BUFFER_SIZE)
            commande = json.loads(commande_data.decode())
            action = commande.get('action')
            
            if action == 'upload':
                self.handle_upload(client_socket, address, commande)
            elif action == 'download':
                self.handle_download(client_socket, address, commande)
            elif action == 'list':
                self.handle_list(client_socket)
        
        except Exception as e:
            print(f"✗ Erreur client: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def handle_upload(self, client_socket, address, commande):
        """Recevoir un fichier chiffré"""
        filename = commande['filename']
        file_size = commande['file_size']
        original_hash = commande['hash']
        password = commande['password']
        
        print(f"  Upload: {filename} ({file_size / 1024 / 1024:.2f} MB)")
        
        # Créer la clé depuis le mot de passe
        cipher = self.creer_cle_depuis_mdp(password)
        
        # Recevoir et stocker le fichier chiffré
        received_size = 0
        sha256 = hashlib.sha256()
        filename_chiffre = f"{filename}.encrypted"
        
        with open(filename_chiffre, 'wb') as f:
            while received_size < file_size:
                try:
                    to_read = min(CHUNK_SIZE, file_size - received_size)
                    chunk_encrypted = client_socket.recv(to_read)
                    if not chunk_encrypted:
                        break
                    
                    f.write(chunk_encrypted)
                    sha256.update(chunk_encrypted)
                    received_size += len(chunk_encrypted)
                    
                    progress = (received_size / file_size) * 100
                    print(f"  Réception: {progress:.1f}%", end='\r')
                except Exception as e:
                    print(f"\n  Erreur: {e}")
                    break
        
        received_hash = sha256.hexdigest()
        
        if received_hash == original_hash:
            print(f"\n✓ Fichier stocké chiffré!")
            self.fichiers_disponibles[filename_chiffre] = {
                'hash': original_hash,
                'size': file_size,
                'is_encrypted': True,
                'original_name': filename
            }
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
            os.remove(filename_chiffre)
    
    def handle_download(self, client_socket, address, commande):
        """Envoyer un fichier chiffré"""
        filename = commande['filename']
        
        if not os.path.exists(filename):
            print(f"  ✗ Fichier non trouvé: {filename}")
            client_socket.send(json.dumps({'error': 'not_found'}).encode())
            return
        
        try:
            file_size = os.path.getsize(filename)
            file_hash = self.calculer_hash(filename)
            
            # Envoyer les métadonnées
            metadata = {
                'filename': filename,
                'file_size': file_size,
                'hash': file_hash
            }
            client_socket.send(json.dumps(metadata).encode() + b'\n[END_METADATA]\n')
            
            print(f"  Download: {filename} ({file_size / 1024 / 1024:.2f} MB)")
            
            # Envoyer le fichier
            sent_size = 0
            with open(filename, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    client_socket.sendall(chunk)
                    sent_size += len(chunk)
                    
                    progress = (sent_size / file_size) * 100
                    print(f"  Envoi: {progress:.1f}%", end='\r')
            
            print(f"\n✓ Fichier envoyé!")
        
        except Exception as e:
            print(f"✗ Erreur download: {e}")
    
    def handle_list(self, client_socket):
        """Lister les fichiers disponibles"""
        try:
            fichiers = []
            for filename in os.listdir('.'):
                if filename.endswith('.encrypted'):
                    size = os.path.getsize(filename)
                    original_name = self.fichiers_disponibles.get(filename, {}).get('original_name', filename)
                    fichiers.append({
                        'filename': filename,
                        'original_name': original_name,
                        'size': size
                    })
            
            response = json.dumps(fichiers)
            client_socket.send(response.encode())
        except Exception as e:
            print(f"✗ Erreur list: {e}")
            client_socket.send(b'[]')
    
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
        """Démarrer le nœud P2P"""
        self.server_thread = threading.Thread(target=self.transfer.start_server)
        self.server_thread.daemon = True
        self.server_thread.start()
        time.sleep(0.5)
    
    def envoyer_fichier(self, filepath: str, host: str, port: int, password: str):
        """Envoyer et chiffrer un fichier"""
        if not os.path.exists(filepath):
            print(f"✗ Fichier non trouvé: {filepath}")
            return
        
        client_socket = None
        try:
            file_size = os.path.getsize(filepath)
            filename = os.path.basename(filepath)
            
            # Créer la clé depuis le mot de passe
            cipher = self.transfer.creer_cle_depuis_mdp(password)
            
            # Préparer les métadonnées
            metadata = {
                'action': 'upload',
                'filename': filename,
                'file_size': file_size,
                'password': password  # Le hash du mot de passe est utilisé côté réception
            }
            
            # Connecter et envoyer
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10)
            client_socket.connect((host, port))
            print(f"→ Connecté à {host}:{port}")
            
            # Envoyer la commande
            client_socket.send(json.dumps(metadata).encode())
            time.sleep(0.1)
            
            print(f"  Fichier: {filename} ({file_size / 1024 / 1024:.2f} MB)")
            print(f"  Chiffrement avec mot de passe...")
            
            # Envoyer le fichier chiffré
            sent_size = 0
            sha256 = hashlib.sha256()
            with open(filepath, 'rb') as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    chunk_encrypted = cipher.encrypt(chunk)
                    client_socket.sendall(chunk_encrypted)
                    sha256.update(chunk_encrypted)
                    sent_size += len(chunk_encrypted)
                    
                    progress = (sent_size / file_size) * 100
                    print(f"  Envoi: {progress:.1f}%", end='\r')
            
            file_hash = sha256.hexdigest()
            metadata['hash'] = file_hash
            
            print(f"\n✓ Fichier envoyé chiffré!")
            
            # Attendre confirmation
            try:
                client_socket.settimeout(5)
                response = client_socket.recv(1024)
                if response == b'OK':
                    print("✓ Reçu et stocké par le destinataire!")
            except socket.timeout:
                print("⚠ Pas de confirmation reçue")
        
        except ConnectionRefusedError:
            print(f"✗ Impossible de se connecter à {host}:{port}")
        except Exception as e:
            print(f"✗ Erreur: {e}")
        finally:
            if client_socket:
                try:
                    client_socket.close()
                except:
                    pass
    
    def telecharger_fichier(self, filename: str, host: str, port: int, password: str):
        """Télécharger et déchiffrer un fichier"""
        client_socket = None
        try:
            cipher = self.transfer.creer_cle_depuis_mdp(password)
            
            # Connecter et télécharger
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10)
            client_socket.connect((host, port))
            print(f"→ Connecté à {host}:{port}")
            
            # Demander le fichier
            commande = {
                'action': 'download',
                'filename': filename
            }
            client_socket.send(json.dumps(commande).encode())
            
            # Recevoir les métadonnées
            metadata_json = b''
            while b'\n[END_METADATA]\n' not in metadata_json:
                chunk = client_socket.recv(BUFFER_SIZE)
                if not chunk:
                    break
                metadata_json += chunk
            
            metadata_str = metadata_json.decode().split('\n[END_METADATA]\n')[0]
            metadata = json.loads(metadata_str)
            
            file_size = metadata['file_size']
            original_hash = metadata['hash']
            nom_dechiffre = filename.replace('.encrypted', '_decrypted')
            
            print(f"  Fichier: {filename} ({file_size / 1024 / 1024:.2f} MB)")
            print(f"  Déchiffrement...")
            
            # Recevoir, déchiffrer et sauvegarder
            received_size = 0
            sha256 = hashlib.sha256()
            with open(nom_dechiffre, 'wb') as f:
                while received_size < file_size:
                    to_read = min(CHUNK_SIZE, file_size - received_size)
                    chunk_encrypted = client_socket.recv(to_read)
                    if not chunk_encrypted:
                        break
                    
                    chunk_decrypted = cipher.decrypt(chunk_encrypted)
                    f.write(chunk_decrypted)
                    sha256.update(chunk_encrypted)
                    received_size += len(chunk_encrypted)
                    
                    progress = (received_size / file_size) * 100
                    print(f"  Réception: {progress:.1f}%", end='\r')
            
            received_hash = sha256.hexdigest()
            if received_hash == original_hash:
                print(f"\n✓ Fichier déchiffré et sauvegardé: {nom_dechiffre}")
            else:
                print(f"\n✗ Erreur: Hash ne correspond pas!")
                os.remove(nom_dechiffre)
        
        except ConnectionRefusedError:
            print(f"✗ Impossible de se connecter à {host}:{port}")
        except Exception as e:
            print(f"✗ Erreur: {e}")
        finally:
            if client_socket:
                try:
                    client_socket.close()
                except:
                    pass
    
    def lister_fichiers(self, host: str, port: int):
        """Lister les fichiers disponibles"""
        client_socket = None
        try:
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.settimeout(10)
            client_socket.connect((host, port))
            
            commande = {'action': 'list'}
            client_socket.send(json.dumps(commande).encode())
            
            response = client_socket.recv(4096).decode()
            fichiers = json.loads(response)
            
            print(f"\nFichiers disponibles sur {host}:{port}:")
            for f in fichiers:
                print(f"  - {f['original_name']} ({f['filename']}) - {f['size'] / 1024 / 1024:.2f} MB")
        
        except Exception as e:
            print(f"✗ Erreur: {e}")
        finally:
            if client_socket:
                try:
                    client_socket.close()
                except:
                    pass
    
    def stop(self):
        """Arrêter le nœud"""
        self.transfer.arreter()


# Exemple d'utilisation
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        mode = sys.argv[1]
        
        if mode == "server":
            port = int(sys.argv[2]) if len(sys.argv) > 2 else 5000
            node = P2PNode(port)
            node.start()
            print("Nœud P2P actif (Ctrl+C pour arrêter)")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n✓ Arrêt...")
                node.stop()
        
        elif mode == "send" and len(sys.argv) > 5:
            filepath = sys.argv[2]
            host = sys.argv[3]
            port = int(sys.argv[4])
            password = sys.argv[5]
            
            node = P2PNode()
            node.start()
            time.sleep(0.5)
            node.envoyer_fichier(filepath, host, port, password)
        
        elif mode == "download" and len(sys.argv) > 5:
            filename = sys.argv[2]
            host = sys.argv[3]
            port = int(sys.argv[4])
            password = sys.argv[5]
            
            node = P2PNode()
            node.start()
            time.sleep(0.5)
            node.telecharger_fichier(filename, host, port, password)
        
        elif mode == "list" and len(sys.argv) > 3:
            host = sys.argv[2]
            port = int(sys.argv[3])
            
            node = P2PNode()
            node.start()
            time.sleep(0.5)
            node.lister_fichiers(host, port)
        
        else:
            print("Usage:")
            print("  Serveur:     python server.py server [port]")
            print("  Envoyer:     python server.py send <fichier> <hôte> <port> <motdepasse>")
            print("  Télécharger: python server.py download <fichier.encrypted> <hôte> <port> <motdepasse>")
            print("  Lister:      python server.py list <hôte> <port>")
    else:
        print("Usage:")
        print("  Serveur:     python server.py server [port]")
        print("  Envoyer:     python server.py send <fichier> <hôte> <port> <motdepasse>")
        print("  Télécharger: python server.py download <fichier.encrypted> <hôte> <port> <motdepasse>")
        print("  Lister:      python server.py list <hôte> <port>")