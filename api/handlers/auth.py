import json
from datetime import datetime, timezone
from .base import BaseHandler
from .sec_utils import hash_token, decrypt_data, get_encryption_key, check_token

class AuthHandler(BaseHandler):

    async def prepare(self):
        super(AuthHandler, self).prepare()

        if self.request.method == 'OPTIONS':
            return

        try:
            token = self.request.headers.get('X-Token')
            if not token:
                raise Exception()
        except Exception:
            self.current_user = None
            self.send_error(400, message='You must provide a token!')
            return

        try:
            token_hash = hash_token(token)
        except Exception:
            self.current_user = None
            self.send_error(400, message='Invalid token format!')
            return

        # search for user with valid token that is not expired
        current_time = datetime.now(timezone.utc).timestamp()
        auth_user = await self.db.users.find_one({
            'token_hash': token_hash,
            'expiresIn': {'$gt': current_time} 
        }, {
            'email': 1,
            'encrypted_personal_data': 1,
            'expiresIn': 1,
            'token_hash': 1
        })

        if not auth_user:
            self.send_error(403, message='Invalid or expired token')
            return
        
        # dcrypt personal data if user has valid token
        try:
            encryption_key = get_encryption_key()
            decrypted_str = decrypt_data(auth_user['encrypted_personal_data'], encryption_key)
            personal_data = json.loads(decrypted_str)
            
            self.current_user = {
                'email': auth_user['email'],
                'display_name': personal_data.get('displayName', auth_user['email']),
                'personal_data': personal_data
            }
            
        except Exception as e:
            self.current_user = {
                'email': auth_user['email'],
                'display_name': auth_user['email'],
                'personal_data': {}
            }
