class EncryptionError(Exception):
    """Base exception for encryption-related errors"""
    pass

class KeyNotFoundError(EncryptionError):
    """Raised when encryption keys are not found"""
    pass

class InvalidKeyError(EncryptionError):
    """Raised when encryption keys are invalid"""
    pass