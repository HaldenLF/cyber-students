import os
import keyring
import json
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.sec_utils import *
from .base import BaseTest


class TestSecUtils(BaseTest):
    
    @classmethod
    def setUpClass(self):
        self.my_app = Application([])
        super().setUpClass()
        
    # check persistent key management
    def test_key_management(self):
        key1 = get_encryption_key()
        key2 = get_encryption_key()
        
        self.assertEqual(key1, key2)

    # test new key generation if key is deleted
    def test_key_regeneration(self):
        
        old_key = get_encryption_key()
        # delete old key
        keyring.delete_password(service, encryption_key)
    
        new_key = get_encryption_key()
        
        self.assertNotEqual(old_key, new_key)
        
    # Test encryption and decryption
    def test_encryption_decryption(self):
        key = get_encryption_key()
        
        test_data = {
            "name": "Alice",
            "address": "123 street",
            "email": "123@email.com",
            "dateOfBirth": "1/1/2026",
            "phoneNumber": "1234567890",
            "ListOfDisabilities": ["First", "Second"]
            }
        test_data_str = json.dumps(test_data)
        
        # encrypt data
        encrypted = encrypt_data(test_data_str, key)
        
        # decrypt data
        decrypted = decrypt_data(encrypted, key)
        
        self.assertEqual(json.loads(decrypted), test_data)
    
    # Test different IV for same key
    def test_unique_iv(self):
        
        key = get_encryption_key()
        test_data_str = json.dumps({"name": "Bob"})
        
        encrypt1 = encrypt_data(test_data_str, key)
        encrypt2 = encrypt_data(test_data_str, key)
        
        self.assertNotEqual(encrypt1, encrypt2)
        
        decrypt1 = decrypt_data(encrypt1, key)
        decrypt2 = decrypt_data(encrypt2, key)
        
        self.assertEqual(decrypt1, test_data_str)
        self.assertEqual(decrypt2, test_data_str)
        
    
    # Test passphrase hashing
    def test_passphrase_hashing(self):
        
        passphrase = "SoSecure"
        salt = os.urandom(32)
        
        test_hash = hash_passphrase(passphrase, salt)
        
        self.assertTrue(check_passphrase(passphrase, salt, test_hash))
        self.assertFalse(check_passphrase("NotSoSecure", salt, test_hash))
        
        # Test same passphrase with different salt produces different hash
        salt2 = os.urandom(32)
        test_hash2 = hash_passphrase(passphrase, salt2)
    
    # Test token hashing
    def test_token_hashing(self):
        
        token = "12345abcde"
        token_hash = hash_token(token)
        
        self.assertTrue(check_token(token, token_hash))
        self.assertFalse(check_token("abcde12345", token_hash))
        
        # Test different token produces different hash
        token2 = "67890fghijk"
        token_hash2 = hash_token(token2)
        self.assertNotEqual(token_hash, token_hash2)
    
    