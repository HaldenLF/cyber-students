import os
import json
from tornado.escape import json_decode
from tornado.httputil import HTTPHeaders
from tornado.ioloop import IOLoop
from tornado.web import Application

from api.handlers.user import UserHandler
from api.handlers.sec_utils import hash_passphrase,hash_token, encrypt_data, get_encryption_key
from .base import BaseTest

class UserHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/user', UserHandler)])
        super().setUpClass()

    async def register(self):
        # hash before storing
        salt = os.urandom(32)
        password_hash = hash_passphrase(self.password, salt)
        
        # Encrypt details
        key = get_encryption_key()
        personal_data = {
            'displayName': self.display_name,
            'address': None,
            'dateOfBirth': None,
            'phoneNumber': None,
            'disabilities': []
        }
        
        personal_data_str = json.dumps(personal_data)
        encrypted_personal_data = encrypt_data(personal_data_str, key)
        
        await self.get_app().db.users.insert_one({
            'email': self.email,
            'password_hash': password_hash,
            'salt': salt,
            'encrypted_personal_data': encrypted_personal_data,
            'token_hash': None,
            'expiresIn': None
        })

    async def login(self):
        token_hash = hash_token(self.token)
        await self.get_app().db.users.update_one({
            'email': self.email
        }, {
            '$set': { 'token_hash': token_hash, 'expiresIn': 2147483647 }
        })

    def setUp(self):
        super().setUp()

        self.email = 'test@test.com'
        self.password = 'testPassword'
        self.display_name = 'testDisplayName'
        self.token = 'testToken'

        IOLoop.current().run_sync(self.register)
        IOLoop.current().run_sync(self.login)

    def test_user(self):
        headers = HTTPHeaders({'X-Token': self.token})

        response = self.fetch('/user', headers=headers)
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(self.email, body_2['email'])
        self.assertEqual(self.display_name, body_2['displayName'])
        self.assertIsNotNone(body_2.get('displayName'))

    def test_user_without_token(self):
        response = self.fetch('/user')
        self.assertEqual(400, response.code)

    def test_user_wrong_token(self):
        headers = HTTPHeaders({'X-Token': 'wrongToken'})

        response = self.fetch('/user')
        self.assertEqual(400, response.code)
