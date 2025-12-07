# -*- coding: utf-8 -*-

from fastapi import APIRouter, Depends, Request, HTTPException, status
from fastapi_users import FastAPIUsers
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from app.models.user import User
from app.managers.user_manager import get_user_manager
from app.core.security import auth_backend
from app.core.config import settings
from app.dbs.redis import get_redis_client
from fastapi.security import HTTPBearer
from passlib.context import CryptContext
from datetime import datetime, timedelta
from fastapi.security import OAuth2PasswordRequestForm
from services.mfa_service import verify_mfa_code
from app.models.mfa_user import (
    UserLogin, UserCreate, UserResponse, Token, 
    MFASetupRequest, MFASetupResponse, MFAVerifyRequest
)
from app.services.mfa_service import AuthService
from app.services.mfa_service import MFAService, MFAEnrollmentManager
from uuid import UUID
from pydantic import BaseModel
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from app.utils.redis_client import get_mfa_failed_attempts
# 初始化日志
from app.core.logger import setup_strcutlogger

logger = setup_strcutlogger()

router = APIRouter(prefix=settings.API_PREFIX)
# 限流器（基于IP）
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.RATE_LIMIT])

# 密码哈希上下文
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# 依赖：检查用户MFA是否锁定
async def check_mfa_lock(user_id: str):
    failed_attempts = await get_mfa_failed_attempts(user_id)
    if failed_attempts >= settings.MFA_MAX_FAILED_ATTEMPTS:
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=f"MFA验证失败次数过多，账户锁定{settings.MFA_LOCK_DURATION_MINUTES}分钟"
        )
    return user_id

# Pydantic 模型
class LoginRequest(BaseModel):
    username: str
    password: str
    mfa_code: str | None = None  # MFA动态码（启用MFA时必填）

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime

# 验证密码
def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# 生成JWT Token
def create_access_token(subject: str) -> tuple[str, datetime]:
    expires_at = datetime.utcnow() + timedelta(minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": subject, "exp": expires_at}
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt, expires_at

# 登录接口（账号密码 + MFA）
@router.post("/login", response_model=TokenResponse)
@limiter.limit(settings.RATE_LIMIT)
async def login(
    request: Request,
    req: LoginRequest,
    db: AsyncSession = Depends(get_db)
):
    # 1. 验证账号密码
    user = await get_user_by_username(db, req.username)
    if not user or not verify_password(req.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    
    # 2. 检查MFA是否启用
    if user.mfa_enabled:
        # 检查MFA是否锁定
        await check_mfa_lock(user.id)
        # 检查MFA动态码是否提供
        if not req.mfa_code:
            raise HTTPException(status_code=400, detail="请提供MFA动态码")
        # 3. 验证MFA动态码
        mfa_secret = await get_user_mfa_secret(db, user.id)
        if not mfa_secret:
            raise HTTPException(status_code=500, detail="MFA密钥配置异常")
        if not await verify_mfa_code(mfa_secret, req.mfa_code):
            # 增加失败次数
            failed_attempts = await increment_mfa_failed_attempts(user.id)
            # 达到最大失败次数，锁定MFA
            if failed_attempts >= settings.MFA_MAX_FAILED_ATTEMPTS:
                await update_user_mfa_lock(db, user.id, lock=True)
                raise HTTPException(
                    status_code=423,
                    detail=f"MFA验证失败次数过多，账户锁定{settings.MFA_LOCK_DURATION_MINUTES}分钟"
                )
            raise HTTPException(
                status_code=401,
                detail=f"MFA动态码错误，剩余尝试次数：{settings.MFA_MAX_FAILED_ATTEMPTS - failed_attempts}"
            )
        # 重置失败次数
        await reset_mfa_failed_attempts(user.id)
    
    # 4. 生成JWT Token
    access_token, expires_at = create_access_token(user.id)
    return TokenResponse(access_token=access_token, expires_at=expires_at)

# ========== 分布式速率限制（Redis） ==========
limiter = Limiter(
    key_func=get_remote_address,
    storage_uri=settings.REDIS_URL,
    storage_options={"password": settings.REDIS_PASSWORD.get_secret_value() if settings.REDIS_PASSWORD else None}
)

router = APIRouter(prefix=settings.API_PREFIX)
router.state.limiter = limiter
router.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# ========== 初始化FastAPI-Users ==========
fastapi_users = FastAPIUsers[User, UUID](
    get_user_manager,
    [auth_backend]
)

# ========== 带速率限制的认证路由 ==========
# 登录接口（5次/分钟）
@router.post("/auth/jwt/login")
@limiter.limit(settings.RATE_LIMIT_LOGIN)
async def login_with_rate_limit(request: Request):
    return await fastapi_users.get_auth_router(auth_backend).routes[0].endpoint(request)

# 注册接口（10次/小时）
@router.post("/auth/register")
@limiter.limit(settings.RATE_LIMIT_REGISTER)
async def register_with_rate_limit(request: Request):
    return await fastapi_users.get_register_router().routes[0].endpoint(request)

# 密码重置请求（3次/小时）
@router.post("/auth/reset-password")
@limiter.limit(settings.RATE_LIMIT_RESET_PASSWORD)
async def reset_password_with_rate_limit(request: Request):
    return await fastapi_users.get_reset_password_router().routes[0].endpoint(request)

# ========== 注销接口（吊销Token） ==========
current_active_user = fastapi_users.current_user(active=True)

@router.post("/auth/logout")
async def logout(request: Request, user: User = Depends(current_active_user)):
    """注销接口（吊销Token）"""
    try:
        token = request.headers.get("Authorization").split(" ")[1]
        await revoke_token(token)
        return {"message": "Successfully logged out"}
    except Exception as e:
        logger.error("Logout failed", error=str(e))
        raise HTTPException(status_code=400, detail="Logout failed") from e
    

security = HTTPBearer()

@router.post("/register", response_model=UserResponse)
async def register(
    user_data: UserCreate,
    db: Session = Depends(get_db),
    background_tasks: BackgroundTasks = None
):
    """用户注册"""
    # 检查邮箱是否已存在
    existing_user = db.query(User).filter(User.email == user_data.email).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # 创建用户
    hashed_password = AuthService.get_password_hash(user_data.password)
    user = User(
        email=user_data.email,
        full_name=user_data.full_name,
        hashed_password=hashed_password
    )
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return user

@router.post("/login", response_model=Token)
async def login(
    login_data: UserLogin,
    db: Session = Depends(get_db),
    redis=Depends(get_redis)
):
    """用户登录（支持 MFA）"""
    # 验证基础凭证
    user = AuthService.authenticate_user(db, login_data.email, login_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password"
        )
    
    mfa_service = MFAService(redis)
    
    # 如果用户启用了 MFA 但未提供令牌
    if user.mfa_enabled and not login_data.mfa_token:
        return Token(mfa_required=True)
    
    # 如果提供了 MFA 令牌，进行验证
    if user.mfa_enabled and login_data.mfa_token:
        if not mfa_service.verify_totp(user.mfa_secret, login_data.mfa_token):
            # 记录失败的尝试
            await mfa_service.store_mfa_attempt(user.id, False)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid MFA token"
            )
        
        # 记录成功尝试
        await mfa_service.store_mfa_attempt(user.id, True)
    
    # 创建令牌
    access_token = AuthService.create_access_token(data={"sub": user.email})
    refresh_token = AuthService.create_refresh_token(data={"sub": user.email})
    
    return Token(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer"
    )

@router.post("/mfa/setup")
async def setup_mfa(
    request: MFASetupRequest,
    current_user: User = Depends(get_current_user),
    redis=Depends(get_redis)
):
    """设置 MFA"""
    mfa_service = MFAService(redis)
    enrollment_manager = MFAEnrollmentManager(mfa_service)
    
    enrollment_data = await enrollment_manager.start_enrollment(current_user)
    
    return {
        "qr_code": enrollment_data['qr_code'],
        "manual_entry_key": enrollment_data['manual_entry_key'],
        "backup_codes": enrollment_data['backup_codes']
    }

@router.post("/mfa/verify")
async def verify_mfa_setup(
    request: MFAVerifyRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    redis=Depends(get_redis)
):
    """验证 MFA 设置"""
    mfa_service = MFAService(redis)
    
    # 在实际实现中，应从安全存储中获取密钥
    if not mfa_service.verify_totp(current_user.mfa_secret, request.token):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid MFA token"
        )
    
    # 启用 MFA
    current_user.mfa_enabled = True
    db.commit()
    
    return {"message": "MFA enabled successfully"}

@router.post("/mfa/disable")
async def disable_mfa(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """禁用 MFA"""
    current_user.mfa_enabled = False
    current_user.mfa_secret = None
    db.commit()
    
    return {"message": "MFA disabled successfully"}

# ========== 其他内置路由 ==========
router.include_router(
    fastapi_users.get_auth_router(auth_backend),
    prefix="/auth/jwt",
    tags=["auth"],
    exclude=["/login"]  # 排除默认登录，使用带速率限制的版本
)
router.include_router(fastapi_users.get_verify_router(), prefix="/auth", tags=["auth"])
router.include_router(fastapi_users.get_users_router(), prefix="/users", tags=["users"])
