# -*- coding: utf-8 -*-

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from database.session import get_db
from services.mfa_service import generate_mfa_secret, verify_mfa_code
from crud.user_crud import get_user_by_id, update_user_mfa_secret
from utils.redis_client import get_mfa_temp_secret, reset_mfa_failed_attempts
from dependencies import limiter, check_mfa_lock
from fastapi import APIRouter, Depends, HTTPException, status, Request
from crud.user_crud import get_user_by_id, update_user_password
from services.mfa_service import verify_mfa_code
from dependencies import limiter, check_mfa_lock
from utils.redis_client import reset_mfa_failed_attempts
# 初始化日志
from app.core.logger import setup_strcutlogger

logger = setup_strcutlogger()

router = APIRouter(prefix="/user", tags=["用户管理"])

class UpdatePasswordRequest(BaseModel):
    user_id: str
    old_password: str
    new_password: str
    mfa_code: str  # 二次MFA验证

@router.post("/update-password")
@limiter.limit(settings.RATE_LIMIT)
async def update_password(
    request: Request,
    req: UpdatePasswordRequest,
    db: AsyncSession = Depends(get_db)
):
    # 1. 检查用户
    user = await get_user_by_id(db, req.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    
    # 2. 验证旧密码
    if not verify_password(req.old_password, user.hashed_password):
        raise HTTPException(status_code=400, detail="旧密码错误")
    
    # 3. 二次MFA验证（敏感操作强制验证）
    if user.mfa_enabled:
        await check_mfa_lock(user.id)
        mfa_secret = await get_user_mfa_secret(db, user.id)
        if not await verify_mfa_code(mfa_secret, req.mfa_code):
            await increment_mfa_failed_attempts(user.id)
            raise HTTPException(status_code=401, detail="MFA动态码错误")
        await reset_mfa_failed_attempts(user.id)
    
    # 4. 更新密码
    hashed_new_password = pwd_context.hash(req.new_password)
    await update_user_password(db, req.user_id, hashed_new_password)
    return {"status": "success", "message": "密码更新成功"}

router = APIRouter(prefix="/mfa", tags=["MFA 管理"])

# 敏感操作二次 MFA 验证 
# 企业级场景中，修改密码、转账等敏感操作需二次 MFA 验证：

# Pydantic 模型
class MfaBindVerifyRequest(BaseModel):
    user_id: str
    code: str  # 用户输入的TOTP动态码

class MfaBindResponse(BaseModel):
    secret: str  # 临时密钥（供用户备份）
    qrcode_url: str
    message: str = "请使用谷歌验证器扫码绑定，然后验证动态码完成绑定"

# 1. 生成MFA密钥和二维码
@router.get("/generate/{user_id}", response_model=MfaBindResponse)
@limiter.limit(settings.RATE_LIMIT)
async def generate_mfa(
    request: Request,
    user_id: str,
    db: AsyncSession = Depends(get_db)
):
    # 检查用户是否存在
    user = await get_user_by_id(db, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    # 生成密钥和二维码
    secret, qrcode_url = await generate_mfa_secret(user_id)
    return MfaBindResponse(secret=secret, qrcode_url=qrcode_url)

# 2. 验证MFA动态码，完成绑定
@router.post("/bind/verify")
@limiter.limit(settings.RATE_LIMIT)
async def verify_mfa_bind(
    request: Request,
    req: MfaBindVerifyRequest,
    db: AsyncSession = Depends(get_db),
    user_id: str = Depends(check_mfa_lock)
):
    # 检查用户
    user = await get_user_by_id(db, req.user_id)
    if not user:
        raise HTTPException(status_code=404, detail="用户不存在")
    # 获取缓存的临时密钥
    temp_secret = await get_mfa_temp_secret(req.user_id)
    if not temp_secret:
        raise HTTPException(status_code=400, detail="临时密钥已过期，请重新生成")
    # 验证动态码
    if not await verify_mfa_code(temp_secret, req.code):
        raise HTTPException(status_code=400, detail="动态码错误或过期")
    # 绑定成功：更新数据库（加密存储密钥）
    await update_user_mfa_secret(db, req.user_id, temp_secret)
    # 重置失败次数
    await reset_mfa_failed_attempts(req.user_id)
    return {"status": "success", "message": "MFA绑定成功，请启用MFA登录"}
