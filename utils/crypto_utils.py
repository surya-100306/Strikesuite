#!/usr/bin/env python3
"""
Cryptography Utilities
Cryptographic functions and utilities
"""

import hashlib
import base64
import secrets
import logging
from typing import Optional, Tuple

# Try to import cryptography, fallback to basic implementations if not available
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    Fernet = None
    hashes = None
    PBKDF2HMAC = None

class CryptoUtils:
    """
    Cryptographic utility functions
    """
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def generate_key(self, password: str, salt: Optional[bytes] = None) -> bytes:
        """
        Generate encryption key from password
        
        Args:
            password: Password string
            salt: Salt bytes (optional)
            
        Returns:
            Encryption key
        """
        try:
            if not CRYPTOGRAPHY_AVAILABLE:
                # Fallback to simple key generation
                if salt is None:
                    salt = secrets.token_bytes(16)
                combined = password.encode() + salt
                key = hashlib.sha256(combined).digest()
                return base64.urlsafe_b64encode(key)
            
            if salt is None:
                salt = secrets.token_bytes(16)
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
            return key
        except Exception as e:
            self.logger.error(f"Failed to generate key: {e}")
            return None
    
    def encrypt_data(self, data: str, key: bytes) -> Optional[bytes]:
        """
        Encrypt data with key
        
        Args:
            data: Data to encrypt
            key: Encryption key
            
        Returns:
            Encrypted data or None if failed
        """
        try:
            if not CRYPTOGRAPHY_AVAILABLE:
                # Fallback to simple XOR encryption
                data_bytes = data.encode()
                key_bytes = key[:len(data_bytes)]
                encrypted = bytes(a ^ b for a, b in zip(data_bytes, key_bytes))
                return base64.b64encode(encrypted)
            
            f = Fernet(key)
            encrypted_data = f.encrypt(data.encode())
            return encrypted_data
        except Exception as e:
            self.logger.error(f"Failed to encrypt data: {e}")
            return None
    
    def decrypt_data(self, encrypted_data: bytes, key: bytes) -> Optional[str]:
        """
        Decrypt data with key
        
        Args:
            encrypted_data: Encrypted data
            key: Decryption key
            
        Returns:
            Decrypted data or None if failed
        """
        try:
            if not CRYPTOGRAPHY_AVAILABLE:
                # Fallback to simple XOR decryption
                try:
                    decoded_data = base64.b64decode(encrypted_data)
                    key_bytes = key[:len(decoded_data)]
                    decrypted = bytes(a ^ b for a, b in zip(decoded_data, key_bytes))
                    return decrypted.decode()
                except:
                    return None
            
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_data)
            return decrypted_data.decode()
        except Exception as e:
            self.logger.error(f"Failed to decrypt data: {e}")
            return None
    
    def hash_password(self, password: str, salt: Optional[str] = None) -> Tuple[str, str]:
        """
        Hash password with salt
        
        Args:
            password: Password to hash
            salt: Salt string (optional)
            
        Returns:
            Tuple of (hashed_password, salt)
        """
        try:
            if salt is None:
                salt = secrets.token_hex(16)
            
            # Combine password and salt
            combined = password + salt
            
            # Hash with SHA-256
            hashed = hashlib.sha256(combined.encode()).hexdigest()
            
            return hashed, salt
        except Exception as e:
            self.logger.error(f"Failed to hash password: {e}")
            return None, None
    
    def verify_password(self, password: str, hashed_password: str, salt: str) -> bool:
        """
        Verify password against hash
        
        Args:
            password: Password to verify
            hashed_password: Stored hash
            salt: Salt used for hashing
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            # Hash the provided password with the same salt
            test_hash, _ = self.hash_password(password, salt)
            return test_hash == hashed_password
        except Exception as e:
            self.logger.error(f"Failed to verify password: {e}")
            return False
    
    def generate_token(self, length: int = 32) -> str:
        """
        Generate random token
        
        Args:
            length: Token length
            
        Returns:
            Random token string
        """
        try:
            return secrets.token_hex(length)
        except Exception as e:
            self.logger.error(f"Failed to generate token: {e}")
            return None
    
    def hash_file(self, filepath: str, algorithm: str = 'sha256') -> Optional[str]:
        """
        Calculate hash of file
        
        Args:
            filepath: Path to file
            algorithm: Hash algorithm (md5, sha1, sha256)
            
        Returns:
            File hash or None if failed
        """
        try:
            hash_obj = hashlib.new(algorithm)
            
            with open(filepath, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_obj.update(chunk)
            
            return hash_obj.hexdigest()
        except Exception as e:
            self.logger.error(f"Failed to hash file {filepath}: {e}")
            return None
    
    def hash_string(self, text: str, algorithm: str = 'sha256') -> str:
        """
        Calculate hash of string
        
        Args:
            text: Text to hash
            algorithm: Hash algorithm (md5, sha1, sha256)
            
        Returns:
            String hash
        """
        try:
            hash_obj = hashlib.new(algorithm)
            hash_obj.update(text.encode())
            return hash_obj.hexdigest()
        except Exception as e:
            self.logger.error(f"Failed to hash string: {e}")
            return None
    
    def encode_base64(self, data: str) -> str:
        """
        Encode string to base64
        
        Args:
            data: String to encode
            
        Returns:
            Base64 encoded string
        """
        try:
            return base64.b64encode(data.encode()).decode()
        except Exception as e:
            self.logger.error(f"Failed to encode base64: {e}")
            return None
    
    def decode_base64(self, encoded_data: str) -> str:
        """
        Decode base64 string
        
        Args:
            encoded_data: Base64 encoded string
            
        Returns:
            Decoded string
        """
        try:
            return base64.b64decode(encoded_data).decode()
        except Exception as e:
            self.logger.error(f"Failed to decode base64: {e}")
            return None
    
    def generate_secure_password(self, length: int = 16) -> str:
        """
        Generate secure random password
        
        Args:
            length: Password length
            
        Returns:
            Secure password string
        """
        try:
            # Character sets
            lowercase = 'abcdefghijklmnopqrstuvwxyz'
            uppercase = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
            digits = '0123456789'
            symbols = '!@#$%^&*()_+-=[]{}|;:,.<>?'
            
            # Combine all characters
            all_chars = lowercase + uppercase + digits + symbols
            
            # Generate password
            password = ''.join(secrets.choice(all_chars) for _ in range(length))
            return password
        except Exception as e:
            self.logger.error(f"Failed to generate secure password: {e}")
            return None
