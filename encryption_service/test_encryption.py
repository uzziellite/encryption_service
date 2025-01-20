import unittest
import os
import shutil
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from encryption import EncryptionService
from key_manager import KeyManager

class TestEncryptionService(unittest.TestCase):
    def setUp(self):
        """Set up a temporary key directory for testing."""
        self.test_key_path = Path('./test_keys')
        self.test_key_path.mkdir(exist_ok=True)
        self.encryption_service = EncryptionService(key_path=self.test_key_path)

    def tearDown(self):
        """Clean up the temporary key directory."""
        shutil.rmtree(self.test_key_path)

    def test_key_generation(self):
        """Test if keys are generated and stored correctly."""
        private_key_path = self.test_key_path / 'private_key.pem'
        public_key_path = self.test_key_path / 'public_key.pem'
        
        self.assertTrue(private_key_path.exists(), "Private key was not generated.")
        self.assertTrue(public_key_path.exists(), "Public key was not generated.")

    def test_encryption_decryption(self):
        """Test encryption and decryption of a message."""
        message = "This is a test message."
        encrypted_data = self.encryption_service.encrypt_message(message)

        print(f"{encrypted_data}")
        
        self.assertIn('encrypted_message', encrypted_data, "Encrypted message missing.")
        self.assertIn('encrypted_key', encrypted_data, "Encrypted key missing.")
        
        decrypted_message = self.encryption_service.decrypt_message(encrypted_data)
        self.assertEqual(decrypted_message, message, "Decrypted message does not match the original.")

        print(f"{decrypted_message}")

class TestKeyManager(unittest.TestCase):
    def setUp(self):
        """Set up a temporary key directory for testing."""
        self.test_key_path = Path('./test_keys_manager')
        self.test_key_path.mkdir(exist_ok=True)
        self.key_manager = KeyManager(key_path=self.test_key_path, key_password=b"test_password")

        # Generate test RSA keys
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def tearDown(self):
        """Clean up the temporary key directory."""
        shutil.rmtree(self.test_key_path)

    def test_secure_directory_creation(self):
        """Test if the secure directory is created with the correct permissions."""
        self.assertTrue(self.test_key_path.exists(), "Key directory was not created.")
        self.assertEqual(oct(self.test_key_path.stat().st_mode)[-3:], '700', "Directory permissions are incorrect.")

    def test_save_and_load_private_key(self):
        """Test saving and loading a private key."""
        self.key_manager.save_private_key(self.private_key)
        loaded_private_key = self.key_manager.load_private_key()
        
        # Ensure the saved and loaded keys are equivalent
        self.assertEqual(
            self.private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ),
            loaded_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ),
            "Private key mismatch after saving and loading."
        )

    def test_save_and_load_public_key(self):
        """Test saving and loading a public key."""
        self.key_manager.save_public_key(self.public_key)
        loaded_public_key = self.key_manager.load_public_key()
        
        # Ensure the saved and loaded keys are equivalent
        self.assertEqual(
            self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            loaded_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            "Public key mismatch after saving and loading."
        )

if __name__ == "__main__":
    unittest.main()
