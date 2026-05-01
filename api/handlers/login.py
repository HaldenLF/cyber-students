import secrets
from datetime import datetime, timedelta, timezone
from tornado.escape import json_decode
from .sec_utils import hash_token, check_passphrase
from .base import BaseHandler

class LoginHandler(BaseHandler):

    async def generate_token(self, email):
        token = secrets.token_urlsafe(32)
        token_hash = hash_token(token)
        expires_in = (datetime.now(timezone.utc) + timedelta(hours=2)).timestamp()
        

        await self.db.users.find_one_and_update(
            {
            'email': email
            }, 
            {
            '$set': {
                'token_hash': token_hash,
                'expiresIn': expires_in,
                }      
            }   
        )

        return token, expires_in

    async def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            password = body['password']
        except Exception:
            self.send_error(400, message='You must provide an email address and password!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        user = await self.db.users.find_one({
            'email': email
        }, {
            'password_hash': 1,
            'password_salt': 1
        })

        if user is None:
            self.send_error(403, message='The email address and password are invalid!')
            return

        # Verify password hash
        if not check_passphrase(password, user['password_salt'], user['password_hash']):            
            self.send_error(403, message='The email address and password are invalid!')
            return

        token, expires_in = await self.generate_token(email)

        self.set_status(200)
        self.response['token'] = token
        self.response['expiresIn'] = expires_in

        self.write_json()
