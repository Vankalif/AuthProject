from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, HTTPBearer, HTTPAuthorizationCredentials
from passlib.hash import bcrypt
from tortoise.contrib.fastapi import register_tortoise
from tortoise.exceptions import DoesNotExist

from settings import TORTOISE_ORM, JWT_CONFIG
from src.auth import Auth
from src.models import *

auth_handler = Auth()
security = HTTPBearer()
app = FastAPI()


async def authenticate_user(username: str, password: str):
    user = await User.get(username=username)
    if not user:
        return False
    if not auth_handler.verify_password(password, user.password):
        return False
    return user


@app.post("/login", response_model=User_Pydantic_Response_Model)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    # Identification
    user = await auth_handler.usr_ident_by_creds(form_data)

    # Authentication
    auth_handler.verify_password(form_data.password, user.password)

    # Remove tokens from user in database
    await auth_handler.del_access_token(user)
    await auth_handler.del_refresh_token(user)

    # Get Pydantic model for encode in tokens
    user_pydantic_model = await User_Pydantic_Response_Model.from_tortoise_orm(user)

    # Encoding
    jwt_token = auth_handler.encode_token(**user_pydantic_model.dict())
    jwt_refresh_token = auth_handler.encode_refresh_token(**user_pydantic_model.dict())

    # Write tokens in database
    await Token.create(hash_string=jwt_token, user=user, expire_at=JWT_CONFIG['token_expire'])
    await RefreshToken.create(hash_string=jwt_refresh_token,
                              user=user,
                              expire_at=JWT_CONFIG['refresh_token_expire'])

    return await User_Pydantic_Response_Model.from_tortoise_orm(user)


@app.post("/refresh", response_model=Token_Pydantic)
async def new_token(credentials: HTTPAuthorizationCredentials = Security(security)):
    # Identification
    user, refresh_token, access_token = await auth_handler.usr_ident_by_token(credentials)

    # Convert tortoise model into Pydantic model
    user_pydantic = await User_Pydantic.from_tortoise_orm(user)

    # Authentication
    if refresh_token.hash_string == credentials.credentials:
        # Encode Pydantic model into access token
        jwt_token = auth_handler.encode_token(**user_pydantic.dict())

        # Update the token for the user
        await Token.filter(id=user.id).update(hash_string=jwt_token, expire_at=JWT_CONFIG['token_expire'])

        # get updated data
        access_token = await Token.get(user=user)
        access_token_in = Token_Pydantic.from_orm(access_token)

        return access_token_in


@app.post("/signup", response_model=User_Pydantic_Response_Model)
async def create_user(user: User_Pydantic):
    try:
        if await User.get(username=user.username):
            raise HTTPException(
                status_code=409,
                detail="Username already exist"
            )
    except DoesNotExist:
        # Create a user
        user_obj = await User.create(username=user.username,
                                     password=bcrypt.hash(user.password),
                                     email=user.email)

        # Encoder user data in JWT-tokens
        user_pydantic_model = await User_Pydantic_Response_Model.from_tortoise_orm(user_obj)
        access_token = auth_handler.encode_token(**user_pydantic_model.dict())
        refresh_token = auth_handler.encode_refresh_token(**user_pydantic_model.dict())

        # Write tokens into database
        await Token.create(hash_string=access_token, user=user_obj, expire_at=JWT_CONFIG['token_expire'])
        await RefreshToken.create(hash_string=refresh_token,
                                  user=user_obj,
                                  expire_at=JWT_CONFIG['refresh_token_expire'])

        return await User_Pydantic_Response_Model.from_tortoise_orm(user_obj)


@app.get("/secret")
async def secret(credentials: HTTPAuthorizationCredentials = Security(security)):
    token = credentials.credentials
    if auth_handler.decode_token(token):
        return "Secret data"


@app.get("/notsecret")
async def notsecret():
    return JSONResponse(
        content={"not secret data": "123"}
    )

register_tortoise(
    app,
    config=TORTOISE_ORM,
    generate_schemas=True,
    add_exception_handlers=True,
)
