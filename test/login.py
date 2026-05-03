import os
from json import dumps
from tornado.escape import json_decode
from tornado.ioloop import IOLoop
from tornado.web import Application

from .base import BaseTest
from api.handlers.login import LoginHandler
from api.handlers.sec_utils import check_token, hash_passphrase

class LoginHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/login', LoginHandler)])
        super().setUpClass()

    async def register(self):
        # Added salt and hashing
        salt = os.urandom(32)
        password_hash = hash_passphrase(self.password, salt)

        # Updated info to include rest of required data for database
        await self.get_app().db.users.insert_one({
            'email': self.email,
            'password_hash': password_hash,
            'password_salt': salt,
            'persona_info': 'testPersonalInfo',
            'token_hash': None,
            'expiresIn': None
        })

    def setUp(self):
        super().setUp()

        self.email = 'test@test.com'
        self.password = 'testPassword'

        IOLoop.current().run_sync(self.register)

    def test_login(self):
        body = {
            'email': self.email,
            'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertIsNotNone(body_2['token'])
        self.assertIsNotNone(body_2['expiresIn'])
        
        user = IOLoop.current().run_sync(
            lambda: self.get_app().db.users.find_one({'email': self.email})
        )
        
        # Check correct token version is stored
        self.assertIsNotNone(user.get('token_hash'), 'Hashed token should be stored in database')
        
        # verify that stored token matches the returned token
        token = body_2['token']
        self.assertTrue(check_token(token, user['token_hash']), 'Returned token should match stored token hash')

    def test_login_case_insensitive(self):
        body = {
            'email': self.email.swapcase(),
            'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertIsNotNone(body_2['token'])
        self.assertIsNotNone(body_2['expiresIn'])

    def test_login_wrong_email(self):
        body = {
            'email': 'wrongUsername',
            'password': self.password
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(403, response.code)

    def test_login_wrong_password(self):
        body = {
            'email': self.email,
            'password': 'wrongPassword'
        }

        response = self.fetch('/login', method='POST', body=dumps(body))
        self.assertEqual(403, response.code)
