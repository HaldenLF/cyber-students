import json
import os
from tornado.httputil import HTTPHeaders
from tornado.ioloop import IOLoop
from tornado.web import Application
from .base import BaseTest
from api.handlers.auth import AuthHandler
from api.handlers.sec_utils import hash_token, encrypt_data, get_encryption_key

class TestAuthHandler(BaseTest):
    
    @classmethod
    def setUpClass(self):
        
        class testEndpoint(AuthHandler):
            async def get(self):
                self.write("Authenticated")
        
        self.my_app = Application([(r'/test-auth', testEndpoint)])
        super().setUpClass()
    
    async def create_user(self, email, token, expires_in):
        key = get_encryption_key()
        encrypted_data = encrypt_data(json.dumps({'displayName': 'Test'}), key)
        
        
        await self.my_app.db.users.insert_one({
            'email': email,
            'encrypted_personal_data': encrypted_data,
            'token_hash': hash_token(token),
            'expiresIn': expires_in
        })
        
    def setUp(self):
        super().setUp()
        IOLoop.current().run_sync(lambda: self.create_user('test@test.com', 'valid_token', 2147483647))
        
    def test_valid_token(self):
        response = self.fetch('/test-auth', headers=HTTPHeaders({'X-Token': 'valid_token'}))
        self.assertEqual(200, response.code)
        
    def test_missing_token(self):
        response = self.fetch('/test-auth')
        self.assertEqual(400, response.code)
    
    def test_invalid_token(self):
        response = self.fetch('/test-auth', headers=HTTPHeaders({'X-Token': 'invalid_token'}))
        self.assertEqual(403, response.code)