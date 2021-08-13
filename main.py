from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.exceptions import ValidationError
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
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='login')


async def authenticate_user(username: str, password: str):
    user = await User.get(username=username)
    if not user:
        return False
    if not auth_handler.verify_password(password, user.password):
        return False
    return user


@app.post("/login", response_model=User_Pydantic_Response_Model)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user_obj = await authenticate_user(form_data.username, form_data.password)
    if not user_obj:
        raise HTTPException(
            status_code=401,
            detail='Invalid username or password'
        )
    await auth_handler.del_access_token(user_obj)
    await auth_handler.del_refresh_token(user_obj)
    user_pydantic_model = await User_Pydantic_Response_Model.from_tortoise_orm(user_obj)

    jwt_token = auth_handler.encode_token(**user_pydantic_model.dict())
    jwt_refresh_token = auth_handler.encode_refresh_token(**user_pydantic_model.dict())

    await Token.create(hash_string=jwt_token, user=user_obj, expire_at=JWT_CONFIG['token_expire'])
    await RefreshToken.create(hash_string=jwt_refresh_token,
                              user=user_obj,
                              expire_at=JWT_CONFIG['refresh_token_expire'])

    return await User_Pydantic_Response_Model.from_tortoise_orm(user_obj)


@app.post("/refresh", response_model=Token_Pydantic)
async def new_token(credentials: HTTPAuthorizationCredentials = Security(security)):

    refresh_token = credentials.credentials

    # Identification
    token_sub = auth_handler.decode_token(refresh_token)
    user = await User.get(username=token_sub)
    user_pydantic = await User_Pydantic.from_tortoise_orm(user)
    token_obj = await RefreshToken.get(user=user)
    token = await RefreshToken_Pydantic.from_tortoise_orm(token_obj)

    # Authentication
    if token.hash_string == refresh_token:
        await auth_handler.del_access_token(user)
        jwt_token = auth_handler.encode_token(**user_pydantic.dict())
        access_token = await Token.create(hash_string=jwt_token, user=user, expire_at=JWT_CONFIG['token_expire'])
        access_token_in = Token_Pydantic.from_orm(access_token)
        return access_token_in
    raise HTTPException(status_code=401)


@app.post("/signup", response_model=User_Pydantic_Response_Model)
async def create_user(user: User_Pydantic):
    try:
        if await User.get(username=user.username):
            raise HTTPException(
                status_code=409,
                detail="Username already exist"
            )
    except DoesNotExist:
        try:
            user_obj = await User.create(username=user.username,
                                         password=bcrypt.hash(user.password),
                                         email=user.email)

            user_pydantic_model = await User_Pydantic_Response_Model.from_tortoise_orm(user_obj)

            jwt_token = auth_handler.encode_token(**user_pydantic_model.dict())
            jwt_refresh_token = auth_handler.encode_refresh_token(**user_pydantic_model.dict())
            await Token.create(hash_string=jwt_token, user=user_obj, expire_at=JWT_CONFIG['token_expire'])
            await RefreshToken.create(hash_string=jwt_refresh_token,
                                      user=user_obj,
                                      expire_at=JWT_CONFIG['refresh_token_expire'])

            return await User_Pydantic_Response_Model.from_tortoise_orm(user_obj)

        except ValidationError:
            raise HTTPException(
                status_code=422,
                detail="Validation Error"
            )


@app.get("/secret")
async def secret(token: str = Depends(oauth2_scheme)):
    return True


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
