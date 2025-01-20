from cryptography.hazmat.primitives import serialization
import os
from pathlib import Path

class KeyManager:
    def __init__(self, key_path=None, key_password=None):
        """
        :param key_path: Path to the directory where keys are stored.
                         If not provided, defaults to ~/.secure/keys.
        :param key_password: Password for encrypting the private key.
                             If not provided, defaults to None.
        """
        self.KEY_PATH = Path(key_path or os.getenv('ENCRYPTION_KEY_PATH', Path.home() / '.secure' / 'keys'))
        self.KEY_PASSWORD = key_password or os.getenv('ENCRYPTION_KEY_PASSWORD', '').encode() or None
        self._ensure_secure_directory()
    
    def _ensure_secure_directory(self):
        """Create secure key directory with restricted permissions."""
        if not self.KEY_PATH.exists():
            self.KEY_PATH.mkdir(parents=True, mode=0o700)
        else:
            os.chmod(self.KEY_PATH, 0o700)
    
    def save_private_key(self, private_key):
        """Save private key with encryption and restricted permissions."""
        private_key_path = self.KEY_PATH / 'private_key.pem'
        encryption_algorithm = (
            serialization.BestAvailableEncryption(self.KEY_PASSWORD)
            if self.KEY_PASSWORD
            else serialization.NoEncryption()
        )
        with open(private_key_path, 'wb') as f:
            os.chmod(private_key_path, 0o600)
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            ))
    
    def save_public_key(self, public_key):
        """Save public key with appropriate permissions."""
        public_key_path = self.KEY_PATH / 'public_key.pem'
        with open(public_key_path, 'wb') as f:
            os.chmod(public_key_path, 0o644)
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    
    def load_private_key(self):
        """Load private key with password if provided."""
        private_key_path = self.KEY_PATH / 'private_key.pem'
        if not private_key_path.exists():
            raise FileNotFoundError("Private key not found")
        with open(private_key_path, 'rb') as f:
            return serialization.load_pem_private_key(
                f.read(),
                password=self.KEY_PASSWORD
            )
    
    def load_public_key(self):
        """Load public key."""
        public_key_path = self.KEY_PATH / 'public_key.pem'
        if not public_key_path.exists():
            raise FileNotFoundError("Public key not found")
        with open(public_key_path, 'rb') as f:
            return serialization.load_pem_public_key(f.read())
