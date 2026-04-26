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
        print("Testing key management...")
        key1 = get_encryption_key()
        print(f"First check: {key1.hex()}")
        key2 = get_encryption_key()
        print(f"Second Check: {key2.hex()}\n\n")
        
        self.assertEqual(key1, key2)

    # test new key generation if key is deleted
    def test_key_regeneration(self):
        print("Testing key regeneration...")
        
        old_key = get_encryption_key()
        print(f"Old key: {old_key.hex()}")
        # delete old key
        keyring.delete_password(service, encryption_key)
        print("Old key deleted.")
    
        new_key = get_encryption_key()
        print(f"New Key: {new_key.hex()}\n\n")
        
        self.assertNotEqual(old_key, new_key)
        
    # Test encryption and decryption
    def test_encryption_decryption(self):
        print("Testing encryption and decryption...")
        key = get_encryption_key()
        
        test_data = {
            "name": "Alice",
            "address": "123 street",
            "dateOfBirth": "1/1/2026",
            "phoneNumber": "1234567890",
            "ListOfDisabilities": ["First", "Second"]
            }
        test_data_str = json.dumps(test_data)
        print(f"Test Data: {test_data_str}")
        
        # encrypt data
        encrypted = encrypt_data(test_data_str, key)
        print(f"Encrypted Data: {encrypted.hex()}")
        
        # decrypt data
        decrypted = decrypt_data(encrypted, key)
        print(f"Decrypted Data: {json.loads(decrypted)}\n\n")
        
        self.assertEqual(json.loads(decrypted), test_data)
    
    # Test different IV for same key
    def test_unique_iv(self):
        print("Testing unique IV for key...")
        
        key = get_encryption_key()
        test_data_str = json.dumps({"name": "Bob"})
        
        encrypt1 = encrypt_data(test_data_str, key)
        encrypt2 = encrypt_data(test_data_str, key)
        
        self.assertNotEqual(encrypt1, encrypt2)
        print(f"Encryption 1: {encrypt1.hex()}")
        print(f"Encryption 2: {encrypt2.hex()}\n")
        
        decrypt1 = decrypt_data(encrypt1, key)
        decrypt2 = decrypt_data(encrypt2, key)
        print(f"Decrypted 1: {decrypt1}")
        print(f"Decrypted 2: {decrypt2}\n\n")
        self.assertEqual(decrypt1, test_data_str)
        self.assertEqual(decrypt2, test_data_str)
        
    
    # Test passphrase hashing
    def test_passphrase_hashing(self):
        print("Testing passphrase hashing...")
        
        passphrase = "SoSecure"
        salt = os.urandom(32)
        
        test_hash = hash_passphrase(passphrase, salt)
        print(f"Hash: {test_hash.hex()}")
        
        self.assertTrue(check_passphrase(passphrase, salt, test_hash))
        self.assertFalse(check_passphrase("NotSoSecure", salt, test_hash))
        
        # Test same passphrase with different salt produces different hash
        salt2 = os.urandom(32)
        test_hash2 = hash_passphrase(passphrase, salt2)
        print(f"Hash with different salt: {test_hash2.hex()}\n\n")
    
    # Test token hashing
    def test_token_hashing(self):
        print("Testing token hashing...")
        
        token = "12345abcde"
        token_hash = hash_token(token)
        print(f"Token hash: {token_hash.hex()}\n")
        
        self.assertTrue(check_token(token, token_hash))
        self.assertFalse(check_token("abcde12345", token_hash))
        
        # Test different token produces different hash
        token2 = "67890fghijk"
        token_hash2 = hash_token(token2)
        self.assertNotEqual(token_hash, token_hash2)
        print(f"Different token hash: {token_hash2.hex()}\n\n")
    
    