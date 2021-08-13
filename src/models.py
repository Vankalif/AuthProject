from tortoise import fields, Tortoise
from tortoise.models import Model
from tortoise.contrib.pydantic import pydantic_model_creator


class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(30, unique=True)
    email = fields.CharField(50)
    password = fields.CharField(128)
    created_at = fields.DatetimeField(auto_now_add=True)
    modified_at = fields.DatetimeField(auto_now=True)


class Token(Model):
    id = fields.IntField(pk=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    expire_at = fields.DatetimeField()
    hash_string = fields.TextField()
    user = fields.ForeignKeyField("models.User", "token")


class RefreshToken(Model):
    id = fields.IntField(pk=True)
    created_at = fields.DatetimeField(auto_now_add=True)
    expire_at = fields.DatetimeField()
    hash_string = fields.TextField()
    user = fields.ForeignKeyField("models.User", "refresh_token")


Tortoise.init_models(models_paths=["src.models"], app_label="models")
User_Pydantic = pydantic_model_creator(User, name="User", exclude_readonly=True)
User_Pydantic_Response_Model = pydantic_model_creator(User,
                                                      name='UserResponse',
                                                      exclude=('password',))
Token_Pydantic = pydantic_model_creator(Token, name="Token", exclude=("user",))
RefreshToken_Pydantic = pydantic_model_creator(RefreshToken, name="RefreshToken")

