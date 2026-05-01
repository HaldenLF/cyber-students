import json
from json import dumps
from tornado.escape import json_decode
from tornado.ioloop import IOLoop
from tornado.web import Application
from api.handlers.registration import RegistrationHandler
from api.handlers.sec_utils import get_encryption_key, check_passphrase, decrypt_data
from .base import BaseTest


class RegistrationHandlerTest(BaseTest):

    @classmethod
    def setUpClass(self):
        self.my_app = Application([(r'/registration', RegistrationHandler)])
        super().setUpClass()

    def test_registration(self):
        email = 'test@test.com'
        display_name = 'testDisplayName'
        password = 'testPassword'

        body = {
          'email': email,
          'password': password,
          'displayName': display_name
        }

        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(email, body_2['email'])
        self.assertEqual(display_name, body_2['displayName'])
        
        # Check that user is stored in database
        user = IOLoop.current().run_sync(
          lambda: self.get_app().db.users.find_one({'email': email})
        )
        
        # Check that password not stored in plaintext and salt and hash are stored in database
        self.assertIsNone(user.get('password'), 'Password should not be stored in plaintext')
        self.assertIsNotNone(user.get('password_hash'), 'Password hash should be stored')
        self.assertIsNotNone(user.get('password_salt'), 'Salt should be stored')
        
        # Verify stored hashes match password
        salt = user['password_salt']
        stored_hash = user['password_hash']
        self.assertTrue(check_passphrase(password, salt, stored_hash), 'Stored hashes should match with password')
        # Check encryption
        self.assertIsNone(user.get('personal_info'), 'Personal info should be encrypted')
        
        # Check decryption
        key = get_encryption_key()
        decrypted_str = decrypt_data(user['encrypted_personal_data'], key)
        decrypted_data = json.loads(decrypted_str)
        self.assertEqual(decrypted_data['display_name'], display_name)


    def test_registration_without_display_name(self):
        email = 'test@test.com'

        body = {
          'email': email,
          'password': 'testPassword'
        }

        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        body_2 = json_decode(response.body)
        self.assertEqual(email, body_2['email'])
        self.assertEqual(email, body_2['displayName'])

        # Check that user is stored in database
        user = IOLoop.current().run_sync(
          lambda: self.get_app().db.users.find_one({'email': email})
          )
        
        key = get_encryption_key()
        decrypted_str = decrypt_data(user['encrypted_personal_data'], key)
        decrypted_data = json.loads(decrypted_str)
        self.assertEqual(decrypted_data['display_name'], email)
        

    def test_registration_twice(self):
        body = {
          'email': 'test@test.com',
          'password': 'testPassword',
          'displayName': 'testDisplayName'
        }

        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)

        response_2 = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(409, response_2.code)


    def test_registration_with_extra_info(self):
        body = {
          'email': 'test@test.com',
          'password': 'testPassword',
          'displayName': 'testDisplayName',
          'address': 'testAddress',
          'dateOfBirth': '2026-01-01',
          'phoneNumber': '1234567890',
          'listOfDisabilities': ['first','second']
        }
      
        response = self.fetch('/registration', method='POST', body=dumps(body))
        self.assertEqual(200, response.code)
        
        # Check that user is stored in database
        user = IOLoop.current().run_sync(
          lambda: self.get_app().db.users.find_one({'email': 'test@test.com'})
          )
        
        key = get_encryption_key()
        decrypted_str = decrypt_data(user['encrypted_personal_data'], key)
        decrypted_data = json.loads(decrypted_str)
        self.assertEqual(decrypted_data['display_name'], 'testDisplayName')
        self.assertEqual(decrypted_data['address'], 'testAddress')
        self.assertEqual(decrypted_data['dateOfBirth'], '2026-01-01')
        self.assertEqual(decrypted_data['phoneNumber'], '1234567890')
        self.assertEqual(decrypted_data['listOfDisabilities'], ['first','second'])
        
        