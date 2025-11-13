#!/usr/bin/env python3
"""
Script pour générer les certificats SSL nécessaires au système P2P.

Génère :
- Une autorité de certification (CA) locale
- Un certificat serveur signé par la CA
- Un certificat client signé par la CA

Ces certificats permettent l'authentification mutuelle (mTLS) entre les machines.
"""

import os
import ipaddress
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from datetime import datetime, timedelta, timezone

CERTS_DIR = Path("certs")
CERTS_DIR.mkdir(exist_ok=True)

def generate_ca():
    """
    Génère une autorité de certification (CA) locale.
    
    Returns:
        Tuple (clé privée CA, certificat CA)
    """
    print("🔐 Génération de l'autorité de certification (CA)...")
    
    # Génère une clé privée RSA
    ca_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Crée le certificat CA
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "France"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "P2P File Exchange CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "P2P File Exchange Root CA"),
    ])
    
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=3650)  # 10 ans
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True,
    ).add_extension(
        x509.KeyUsage(
            key_cert_sign=True,
            crl_sign=True,
            digital_signature=True,
            key_encipherment=False,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    ).sign(ca_key, hashes.SHA256(), default_backend())
    
    print("✓ CA générée")
    return ca_key, ca_cert

def generate_certificate(ca_key, ca_cert, common_name: str, cert_type: str):
    """
    Génère un certificat signé par la CA.
    
    Args:
        ca_key: Clé privée de la CA
        ca_cert: Certificat de la CA
        common_name: Nom commun du certificat
        cert_type: Type de certificat ("server" ou "client")
        
    Returns:
        Tuple (clé privée, certificat)
    """
    print(f"🔐 Génération du certificat {cert_type} ({common_name})...")
    
    # Génère une clé privée RSA
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Crée le certificat
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "FR"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "France"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Local"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "P2P File Exchange"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    builder = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.now(timezone.utc)
    ).not_valid_after(
        datetime.now(timezone.utc) + timedelta(days=365)  # 1 an
    )
    
    # Ajoute les extensions selon le type
    if cert_type == "server":
        # Pour le serveur : autorise l'authentification serveur
        builder = builder.add_extension(
            x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                x509.DNSName("localhost"),
            ]),
            critical=False,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=True,
        )
    else:  # client
        # Pour le client : autorise l'authentification client
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([
                x509.ExtendedKeyUsageOID.CLIENT_AUTH,
            ]),
            critical=True,
        )
    
    # Ajoute KeyUsage
    builder = builder.add_extension(
        x509.KeyUsage(
            key_cert_sign=False,
            crl_sign=False,
            digital_signature=True,
            key_encipherment=True,
            content_commitment=False,
            data_encipherment=False,
            key_agreement=False,
            encipher_only=False,
            decipher_only=False
        ),
        critical=True,
    )
    
    cert = builder.sign(ca_key, hashes.SHA256(), default_backend())
    
    print(f"✓ Certificat {cert_type} généré")
    return key, cert

def save_key(key, path: Path):
    """Sauvegarde une clé privée au format PEM."""
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

def save_cert(cert, path: Path):
    """Sauvegarde un certificat au format PEM."""
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def main():
    """Fonction principale pour générer tous les certificats."""
    print("="*60)
    print("  GÉNÉRATION DES CERTIFICATS SSL POUR P2P")
    print("="*60)
    print()
    
    # Vérifie si les certificats existent déjà
    ca_cert_path = CERTS_DIR / "ca-cert.pem"
    if ca_cert_path.exists():
        response = input("⚠️  Des certificats existent déjà. Les regénérer? (o/N): ").strip().lower()
        if response != 'o':
            print("Annulé.")
            return
    
    # Génère la CA
    ca_key, ca_cert = generate_ca()
    save_key(ca_key, CERTS_DIR / "ca-key.pem")
    save_cert(ca_cert, CERTS_DIR / "ca-cert.pem")
    
    # Génère le certificat serveur
    server_key, server_cert = generate_certificate(
        ca_key, ca_cert, "P2P Server", "server"
    )
    save_key(server_key, CERTS_DIR / "server-key.pem")
    save_cert(server_cert, CERTS_DIR / "server-cert.pem")
    
    # Génère le certificat client
    client_key, client_cert = generate_certificate(
        ca_key, ca_cert, "P2P Client", "client"
    )
    save_key(client_key, CERTS_DIR / "client-key.pem")
    save_cert(client_cert, CERTS_DIR / "client-cert.pem")
    
    print()
    print("="*60)
    print("✓ TOUS LES CERTIFICATS ONT ÉTÉ GÉNÉRÉS")
    print("="*60)
    print()
    print("Fichiers générés dans le dossier 'certs/':")
    print("  - ca-cert.pem       (certificat de l'autorité)")
    print("  - ca-key.pem        (clé privée de l'autorité)")
    print("  - server-cert.pem   (certificat serveur)")
    print("  - server-key.pem    (clé privée serveur)")
    print("  - client-cert.pem   (certificat client)")
    print("  - client-key.pem    (clé privée client)")
    print()
    print("⚠️  IMPORTANT:")
    print("   - Copiez le dossier 'certs/' sur les deux machines")
    print("   - Les deux machines doivent utiliser les MÊMES certificats")
    print("   - Ne partagez JAMAIS les clés privées (ca-key.pem, server-key.pem, client-key.pem)")
    print("     en dehors de votre réseau local sécurisé")
    print()

if __name__ == "__main__":
    main()

