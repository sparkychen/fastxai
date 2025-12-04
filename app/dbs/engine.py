# -*- coding: utf-8 -*-

from sqlalchemy.ext.asyncio import (
    create_async_engine, AsyncEngine, AsyncSession, async_sessionmaker
)
from sqlalchemy.pool import QueuePool
from sqlalchemy import text
from typing import Optional, AsyncGenerator, List
import structlog
import asyncio
from tenacity import (
    retry, stop_after_attempt, wait_exponential, retry_if_exception_type
)
from app.core.config import db_settings

logger = structlog.get_logger("db.engine")

# 全局引擎实例（读写分离）
_write_engine: Optional[AsyncEngine] = None
_read_engines: List[AsyncEngine] = []
_session_maker: Optional[async_sessionmaker[AsyncSession]] = None

def init_async_engines() -> None:
    """初始化异步引擎（支持读写分离）"""
    global _write_engine, _read_engines, _session_maker

    # 通用引擎配置（高性能+稳定）
    engine_kwargs = {
        "poolclass": QueuePool,
        "pool_size": db_settings.DB_POOL_SIZE,
        "max_overflow": db_settings.DB_MAX_OVERFLOW,
        "pool_recycle": db_settings.DB_POOL_RECYCLE,
        "pool_timeout": db_settings.DB_POOL_TIMEOUT,
        "pool_pre_ping": db_settings.DB_PRE_PING,  # 连接前检查可用性
        "echo": False,  # 生产环境关闭SQL打印
        "echo_pool": False,  # 关闭连接池日志
        "connect_args": {
            "server_settings": {
                "application_name": "enterprise-fastapi",  # 标识应用连接（便于PG监控）
                "timezone": "UTC",  # 统一时区
            }
        },
    }

    # 1. 写引擎（主库）
    _write_engine = create_async_engine(str(db_settings.POSTGRES_DSN), **engine_kwargs)
    logger.info(
        "Write engine initialized",
        host=db_settings.POSTGRES_HOST,
        pool_size=db_settings.DB_POOL_SIZE
    )

    # 2. 读引擎（从库，轮询负载均衡）
    if db_settings.READ_WRITE_SEPARATION and db_settings.POSTGRES_READ_HOSTS:
        for read_host in filter(None, db_settings.POSTGRES_READ_HOSTS):
            read_dsn = str(db_settings.POSTGRES_DSN).replace(
                db_settings.POSTGRES_HOST, read_host.strip()
            )
            read_engine = create_async_engine(read_dsn, **engine_kwargs)
            _read_engines.append(read_engine)
            logger.info("Read engine initialized", host=read_host.strip())

    # 3. 会话工厂（默认绑定写引擎）
    _session_maker = async_sessionmaker(
        bind=_write_engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,  # 提交后不失效对象（提升性能）
    )

# 数据库操作重试装饰器（处理临时故障）
def db_retry(func):
    @retry(
        stop=stop_after_attempt(db_settings.DB_RETRY_MAX_ATTEMPTS),
        wait=wait_exponential(
            multiplier=db_settings.DB_RETRY_DELAY,
            min=1,
            max=10
        ),
        retry=retry_if_exception_type((
            asyncio.TimeoutError,
            ConnectionRefusedError,
            RuntimeError,  # 连接池耗尽
            Exception  # PG临时错误
        )),
        reraise=True
    )
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            logger.error(
                "DB operation failed (retrying)",
                func=func.__name__,
                error=str(e)
            )
            raise
    return wrapper

# FastAPI依赖：获取异步会话（支持读写分离）
async def get_async_session(
    read_only: bool = False
) -> AsyncGenerator[AsyncSession, None]:
    """
    获取异步会话
    :param read_only: 是否使用读库（轮询负载均衡）
    """
    if not _session_maker:
        init_async_engines()

    session: AsyncSession
    if read_only and db_settings.READ_WRITE_SEPARATION and _read_engines:
        # 轮询选择读引擎（避免单从库过载）
        engine_idx = hash(asyncio.current_task().get_name()) % len(_read_engines)
        read_engine = _read_engines[engine_idx]
        session = async_sessionmaker(
            bind=read_engine,
            autoflush=False,
            autocommit=False,
            expire_on_commit=False
        )()
    else:
        session = _session_maker()

    try:
        yield session
    except Exception as e:
        await session.rollback()
        logger.error("Session error, rolled back", error=str(e))
        raise
    finally:
        await session.close()

# 数据库健康检查（暴露监控指标）
@db_retry
async def check_db_health() -> dict:
    """检查数据库健康状态（含连接池）"""
    if not _write_engine:
        init_async_engines()

    # 1. 测试写连接
    async with _write_engine.begin() as conn:
        write_ping = await conn.execute(text("SELECT 1"))
        write_ok = write_ping.scalar() == 1

    # 2. 测试读连接
    read_ok = True
    if _read_engines:
        for engine in _read_engines:
            async with engine.begin() as conn:
                read_ping = await conn.execute(text("SELECT 1"))
                if read_ping.scalar() != 1:
                    read_ok = False
                    break

    # 3. 连接池状态
    pool_status = {
        "write_pool": {
            "size": _write_engine.pool.size(),
            "checked_out": _write_engine.pool.checkedout(),
            "overflow": _write_engine.pool.overflow(),
        }
    }
    if _read_engines:
        pool_status["read_pools"] = [
            {"size": e.pool.size(), "checked_out": e.pool.checkedout()}
            for e in _read_engines
        ]

    return {
        "status": "healthy" if write_ok and read_ok else "unhealthy",
        "write_ok": write_ok,
        "read_ok": read_ok,
        "pool_status": pool_status,
        "rw_separation": db_settings.READ_WRITE_SEPARATION
    }

# 应用关闭时清理引擎
async def close_async_engines() -> None:
    """关闭所有异步引擎"""
    global _write_engine, _read_engines
    if _write_engine:
        await _write_engine.dispose()
        logger.info("Write engine disposed")
    for engine in _read_engines:
        await engine.dispose()
        logger.info("Read engine disposed")
    _write_engine = None
    _read_engines = []
