from dotenv import dotenv_values
from pathlib import Path
from datetime import datetime, timedelta

env_path = Path('.env')
config_file = dotenv_values(env_path.absolute())

token_expire_time = datetime.utcnow() + timedelta(days=0, minutes=30)
refresh_token_expire_time = datetime.utcnow() + timedelta(days=60)


JWT_CONFIG = {
    "secret": config_file.get('JWT_SECRET'),
    "token_expire": datetime.utcnow() + timedelta(days=0, minutes=30),
    "refresh_token_expire": datetime.utcnow() + timedelta(days=60),
}

db_usr: str = config_file.get('DATABASE_USER')
db_password: str = config_file.get('DATABASE_PASSWORD')
db_address: str = config_file.get('DATABASE_ADDRESS')
db_port: str = config_file.get('DATABASE_PORT')
db_name: str = config_file.get('DATABASE_NAME')

TORTOISE_ORM = {
    "connections": {"postgre": f"postgres://{db_usr}:{db_password}@{db_address}:{db_port}/{db_name}"},
    "apps": {
        "models": {
            "models": ["src.models", "aerich.models"],
            "default_connection": "postgre",
        },
    },
}

