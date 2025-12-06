# -*- coding: utf-8 -*-

import aioredis
import structlog
from app.core.co_config import settings

logger = structlog.get_logger("redis")

# 全局Redis客户端（单例）
_redis_client = None

async def get_redis_client() -> aioredis.Redis:
    """获取Redis客户端（异步单例）"""
    global _redis_client
    if _redis_client is None:
        try:
            _redis_client = aioredis.from_url(
                settings.REDIS_URL,
                password=settings.REDIS_PASSWORD.get_secret_value() if settings.REDIS_PASSWORD else None,
                db=settings.REDIS_DB,
                encoding="utf-8",
                decode_responses=True
            )
            # 健康检查
            await _redis_client.ping()
            logger.info("Redis client initialized successfully")
        except Exception as e:
            logger.error("Failed to initialize Redis client", error=str(e))
            raise
    return _redis_client

async def close_redis_client():
    """关闭Redis客户端"""
    global _redis_client
    if _redis_client:
        await _redis_client.close()
        logger.info("Redis client closed")
