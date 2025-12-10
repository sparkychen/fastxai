# -*- coding: utf-8 -*-


from app.models.user import User
from fastapi_users import FastAPIUsers
from app.core.config import settings
from app.services.user_service import auth_backend, get_user_manager
from app.core.logger import logger


fastapi_users = FastAPIUsers[User, int](
    get_user_manager,
    [auth_backend],
)

current_user = fastapi_users.current_user(active=True)
current_superuser = fastapi_users.current_user(active=True, superuser=True)