# -*- coding: utf-8 -*-

from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from limits.storage import RedisStorage
from limits.strategies import FixedWindowRateLimiter
from fastapi import FastAPI, Request, HTTPException
from redis.asyncio import Redis, RedisCluster
from app.core.config import settings
# 初始化日志
from app.core.logger import setup_strcutlogger

logger = setup_strcutlogger()

# ================= 分布式速率限制 =================
class RedisRateLimiter:
    """基于Redis的分布式速率限制（高可用）"""
    def __init__(self):
        self.storage = RedisStorage(settings.RATE_LIMIT_STORAGE_URL)
        self.limiter = FixedWindowRateLimiter(self.storage)
        # 异步Redis客户端（用于健康检查）
        self.redis = Redis.from_url(settings.RATE_LIMIT_STORAGE_URL)

    async def is_allowed(self, key: str, rate: str) -> bool:
        """检查是否允许请求"""
        try:
            # 健康检查
            if not await self.redis.ping():
                logger.warning("Redis connection failed, bypassing rate limit")
                return True  # Redis故障时降级
            
            # 解析速率（如"100/minute"）
            count, period = rate.split("/")
            count = int(count)
            
            # 检查速率限制
            return self.limiter.hit(f"{key}", count, period)
        except Exception as e:
            logger.error("Rate limit check failed", error=str(e))
            return True  # 异常时降级

# ================= FastAPI集成 =================
def setup_rate_limiting(app: FastAPI):
    """配置速率限制中间件"""
    if not settings.RATE_LIMIT_ENABLED:
        return
    
    # 初始化Limiter
    limiter = Limiter(
        key_func=get_remote_address,
        storage_uri=settings.RATE_LIMIT_STORAGE_URL,
        strategy="fixed-window"
    )
    
    # 注册到app
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
    app.add_middleware(SlowAPIMiddleware)
    
    logger.info("Rate limiting enabled")
    return limiter

# 常用限流依赖
def get_default_rate_limit():
    return settings.RATE_LIMIT_DEFAULT

def get_auth_rate_limit():
    return settings.RATE_LIMIT_AUTH

def get_admin_rate_limit():
    return settings.RATE_LIMIT_ADMIN
