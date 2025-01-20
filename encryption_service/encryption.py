from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
from pathlib import Path

class EncryptionService:
    def __init__(self, key_path=None):
        """
        Initialize the encryption service.

        :param key_path: Path to the directory where keys are stored.
                         If not provided, defaults to ~/.secure/keys.
        """
        self.KEY_SIZE = 4096
        self.KEY_PATH = Path(key_path or os.getenv('ENCRYPTION_KEY_PATH', Path.home() / '.secure' / 'keys'))
        self._ensure_key_directory()
        self._load_or_generate_keys()
        
    def _ensure_key_directory(self):
        """Create keys directory if it doesn't exist."""
        self.KEY_PATH.mkdir(parents=True, exist_ok=True)
        
    def _load_or_generate_keys(self):
        """Load existing keys or generate new ones."""
        private_key_path = self.KEY_PATH / 'private_key.pem'
        public_key_path = self.KEY_PATH / 'public_key.pem'
        
        if not private_key_path.exists() or not public_key_path.exists():
            # Generate new key pair
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.KEY_SIZE
            )
            public_key = private_key.public_key()
            
            # Save private key
            with open(private_key_path, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Save public key
            with open(public_key_path, 'wb') as f:
                f.write(public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ))
        
        # Load keys
        with open(private_key_path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None
            )
        
        with open(public_key_path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(f.read())
    
    def encrypt_message(self, message: str) -> dict:
        """Encrypt a message using hybrid encryption (RSA + AES)."""
        aes_key = os.urandom(32)  # AES key
        iv = os.urandom(16)  # Initialization vector

        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        # Add padding to message
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(message.encode()) + padder.finalize()
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()

        # Encrypt AES key using RSA
        encrypted_key = self.public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return {
            'encrypted_message': base64.b64encode(iv + encrypted_message).decode('utf-8'),
            'encrypted_key': base64.b64encode(encrypted_key).decode('utf-8')
        }

    def decrypt_message(self, encrypted_data: dict) -> str:
        """Decrypt a message using hybrid encryption (RSA + AES)."""
        encrypted_message = base64.b64decode(encrypted_data['encrypted_message'])
        encrypted_key = base64.b64decode(encrypted_data['encrypted_key'])

        # Extract IV and ciphertext
        iv = encrypted_message[:16]
        ciphertext = encrypted_message[16:]

        # Decrypt AES key using RSA
        aes_key = self.private_key.decrypt(
            encrypted_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        # Decrypt the message using AES
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        return data.decode('utf-8')
