# Django Secure Messages

A secure and versatile encryption package for Python applications, including Django support, providing robust 4096-bit RSA encryption and AES-256 for secure message encryption.

## Installation

Install the package via pip:

```bash
pip install encryption_service
```

To include optional Django support:

```bash
pip install encryption_service[django]
```

## Quick Start

### Encrypt and Decrypt Messages

```python
from encryption_service import EncryptionService

# Initialize the encryption service
encryption_service = EncryptionService()

# Encrypt a message
encrypted_data = encryption_service.encrypt_message("Secret message")

# Decrypt the message
decrypted_message = encryption_service.decrypt_message(encrypted_data)

print("Encrypted:", encrypted_data)
print("Decrypted:", decrypted_message)
```

### Key Management Example

```python
from encryption_service.key_manager import KeyManager

# Initialize the key manager
key_manager = KeyManager()

# Generate and save new keys
private_key = key_manager.load_private_key()
public_key = key_manager.load_public_key()

print("Private Key:", private_key)
print("Public Key:", public_key)
```

## Features

- **4096-bit RSA Encryption**: Asymmetric encryption for secure key exchanges.
- **AES-256 Symmetric Encryption**: Ensures fast and secure data encryption.
- **Secure Key Management**: Handles key generation, storage, and retrieval securely.
- **Environment-Based Configuration**: Flexible configuration for diverse environments.
- **Broad Compatibility**: Works seamlessly with any Python module or framework, including Django.

## Configuration

### Environment Variables

- **`ENCRYPTION_KEY_PATH`**: Directory path to store encryption keys (default: `~/.secure/django_keys`).
- **`ENCRYPTION_KEY_PASSWORD`**: Password for encrypting private keys (optional).

### Django Integration

If using Django, add the following to your `settings.py`:

```python
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

ENCRYPTION_SERVICE_SETTINGS = {
    'KEY_PATH': os.path.join(BASE_DIR, 'keys'),
    'KEY_PASSWORD': os.environ.get('ENCRYPTION_KEY_PASSWORD', None),
}
```

## Installation Requirements

- Python 3.8+
- `cryptography` library (automatically installed with this package)

Optional:
- Django 3.2+ for Django-specific features.

## Testing

Run unit tests using:

```bash
pytest
```

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new feature branch.
3. Commit your changes with clear messages.
4. Submit a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

## Support

For questions or support, contact [Uzziel Kibet](mailto:uzzielkk@gmail.com).

