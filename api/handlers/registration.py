import os
import json
from tornado.escape import json_decode
from .base import BaseHandler
from .sec_utils import get_encryption_key, hash_passphrase, encrypt_data

class RegistrationHandler(BaseHandler):

    async def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            password = body['password']
            display_name = body.get('displayName')
            address = body.get('address')
            date_of_birth = body.get('dateOfBirth')
            phone_number = body.get('phoneNumber')
            disabilities = body.get('listOfDisabilities', [])
            
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception('Display name must be a string')
            
        except Exception:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        user = await self.db.users.find_one({
            'email': email
        })

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        salt = os.urandom(32)
        password_hash = hash_passphrase(password, salt)
        
        personal_info = {
            'display_name': display_name,
            'address': address,
            'dateOfBirth': date_of_birth,
            'phoneNumber': phone_number,
            'listOfDisabilities': disabilities
        }
        
        personal_info_str = json.dumps(personal_info)
        
        # Encrypting data
        encryption_key = get_encryption_key()
        encrypted_personal_data = encrypt_data(personal_info_str, encryption_key)

        # Store data
        await self.db.users.insert_one({
            'email': email,
            'password_hash': password_hash,
            'password_salt': salt,
            'encrypted_personal_data': encrypted_personal_data,
            'token_hash': None,
            'expiresIn': None
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name
        self.write_json()
