import jwt
from fastapi import HTTPException
from fastapi.security import OAuth2PasswordRequestForm, HTTPAuthorizationCredentials
from passlib.context import CryptContext
from datetime import datetime, timedelta

from tortoise.exceptions import DoesNotExist, OperationalError

from settings import JWT_CONFIG
from .models import Token, RefreshToken, User


class Auth:
    def __init__(self):
        self.secret = JWT_CONFIG['secret']
        self.hasher = CryptContext(schemes=['bcrypt'])

    def encode_password(self, password):
        return self.hasher.hash(password)

    def verify_password(self, password, encoded_password):
        return self.hasher.verify(password, encoded_password)

    def encode_token(self, **kwargs):
        payload = {
            'exp': datetime.utcnow() + timedelta(days=0, minutes=30),
            'iat': datetime.utcnow(),
            'scope': 'access_token',
            'sub': kwargs.get("username")
        }
        return jwt.encode(
            payload,
            self.secret,
            algorithm='HS256'
        )

    def decode_token(self, token):
        try:
            payload = jwt.decode(token, self.secret, algorithms=['HS256'])
            if payload['scope'] == 'access_token' or payload['scope'] == 'refresh_token':
                return payload['sub']
            raise HTTPException(status_code=401, detail='Scope for the token is invalid')
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Token expired')
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail='Invalid token')

    def encode_refresh_token(self, **kwargs):
        payload = {
            'exp': datetime.utcnow() + timedelta(days=30),
            'iat': datetime.utcnow(),
            'scope': 'refresh_token',
            'sub': kwargs.get("username")
        }
        return jwt.encode(
            payload,
            self.secret,
            algorithm='HS256'
        )

    def refresh_token(self, refresh_token):
        try:
            payload = jwt.decode(refresh_token, self.secret, algorithms=['HS256'])
            if payload['scope'] == 'refresh_token':
                username = payload['sub']
                new_token = self.encode_refresh_token(username=username)
                return new_token
            raise HTTPException(status_code=401, detail='Invalid scope for token')
        except jwt.ExpiredSignatureError:
            raise HTTPException(status_code=401, detail='Refresh token expired')
        except jwt.InvalidTokenError:
            raise HTTPException(status_code=401, detail='Invalid refresh token')

    @staticmethod
    async def usr_ident_by_creds(creds: OAuth2PasswordRequestForm) -> User:
        """
            User identification function. Idents user by login.
            :param creds: an instance of OAuth2PasswordRequestForm
            :return list: Return a User tortoise.models.Model instance
            :raises HTTPException, TypeError
        """
        try:
            if not isinstance(creds, OAuth2PasswordRequestForm):
                raise TypeError

            form_data = creds
            user = await User.get(username=form_data.username)
            return user

        except DoesNotExist:
            raise HTTPException(status_code=401, detail="user or password are invalid")

    async def usr_ident_by_token(self, creds: HTTPAuthorizationCredentials):
        """
            User identification function. Idents user by refresh token.
            :param creds: an instance of HTTPAuthorizationCredentials
            :return list: Return a list of User data - [User, refresh_token, access_token]
            :raises HTTPException, TypeError
        """
        try:
            if not isinstance(creds, HTTPAuthorizationCredentials):
                raise TypeError

            refresh_token = creds.credentials
            token_sub = self.decode_token(refresh_token)
            user = await User.get(username=token_sub)
        except DoesNotExist:
            raise HTTPException(status_code=401, detail="user or password are invalid")

        try:
            access_token = await Token.get(user=user)
        except DoesNotExist:
            raise HTTPException(status_code=500, detail="User was found, but tokens are not")

        return [user, refresh_token, access_token]

    @staticmethod
    async def del_access_token(user):
        try:
            access_token_obj = await Token.get(user=user)
            await access_token_obj.delete()
            return True
        except DoesNotExist:
            raise HTTPException(status_code=500, detail='User was found, but token is not')
        except OperationalError:
            raise HTTPException(status_code=500, detail='User was found, token was found, but can\'t delete it.')

    @staticmethod
    async def del_refresh_token(user):
        try:
            refresh_token_obj = await RefreshToken.get(user=user)
            await refresh_token_obj.delete()
            return True
        except DoesNotExist:
            raise HTTPException(status_code=500, detail='User was found, but refresh token is not')
        except OperationalError:
            raise HTTPException(status_code=500,
                                detail='User was found, refresh token was found, but can\'t delete it.')
