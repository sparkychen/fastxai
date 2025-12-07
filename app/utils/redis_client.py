

# utils/redis_client.py
import redis.asyncio as redis
from app.core.config import settings

# 异步Redis客户端
redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)

# MFA 缓存键前缀
MFA_FAILED_ATTEMPTS_PREFIX = "mfa:failed_attempts:"
MFA_TEMP_SECRET_PREFIX = "mfa:temp_secret:"

async def get_mfa_failed_attempts(user_id: str) -> int:
    """获取MFA验证失败次数（优先缓存）"""
    cache_key = f"{MFA_FAILED_ATTEMPTS_PREFIX}{user_id}"
    attempts = await redis_client.get(cache_key)
    return int(attempts) if attempts else 0

async def increment_mfa_failed_attempts(user_id: str) -> int:
    """增加MFA失败次数，缓存15分钟（与锁定时长一致）"""
    cache_key = f"{MFA_FAILED_ATTEMPTS_PREFIX}{user_id}"
    attempts = await redis_client.incr(cache_key)
    await redis_client.expire(cache_key, settings.MFA_LOCK_DURATION_MINUTES * 60)
    return attempts

async def reset_mfa_failed_attempts(user_id: str) -> None:
    """重置MFA失败次数"""
    cache_key = f"{MFA_FAILED_ATTEMPTS_PREFIX}{user_id}"
    await redis_client.delete(cache_key)

async def set_mfa_temp_secret(user_id: str, secret: str, expire_seconds: int = 300) -> None:
    """缓存临时MFA密钥（绑定流程中，5分钟有效期）"""
    cache_key = f"{MFA_TEMP_SECRET_PREFIX}{user_id}"
    await redis_client.setex(cache_key, expire_seconds, secret)

async def get_mfa_temp_secret(user_id: str) -> str | None:
    """获取临时MFA密钥"""
    cache_key = f"{MFA_TEMP_SECRET_PREFIX}{user_id}"
    return await redis_client.get(cache_key)
