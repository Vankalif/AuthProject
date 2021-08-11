

from passlib.hash import bcrypt
from fastapi import FastAPI, Depends, HTTPException
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.exceptions import ValidationError
from tortoise.contrib.fastapi import register_tortoise
from tortoise.exceptions import DoesNotExist

from settings import TORTOISE_ORM, JWT_CONFIG
from src.models import User, Token, RefreshToken, User_Pydantic, User_Pydantic_Response_Model
from src.auth import Auth

auth_handler = Auth()
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl='token')


async def authenticate_user(username: str, password: str):
    user = await User.get(username=username)
    if not user:
        return False
    if not user.verify_password(password):
        return False
    return user


@app.post("/token")
async def generate_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail='Invalid username or password'
        )
    user_pydantic_model = await User_Pydantic_Response_Model.from_tortoise_orm(user)
    jwt_token = auth_handler.encode_token(**user_pydantic_model.dict())
    token_model = await Token.create(hash_string=jwt_token, user=user)


@app.post("/refresh")
async def refresh_token():
    ...


@app.post("/login")
async def login():
    ...


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
async def secret():
    ...


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
