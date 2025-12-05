# -*- coding: utf-8 -*-

import asyncio
import os
from functools import lru_cache
from typing import AsyncGenerator, List, Dict, Any
import structlog
from sqlalchemy import MetaData, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker, AsyncEngine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import QueuePool
from app.core.config import settings

logger = structlog.get_logger("db")

# 企业级Metadata命名规范（避免约束冲突）
NAMING_CONVENTION = {
    "ix": "ix_%(table_name)s_%(column_0_N_name)s",
    "uq": "uq_%(table_name)s_%(column_0_N_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_N_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s"
}

class Base(DeclarativeBase):
    __abstract__ = True
    metadata = MetaData(naming_convention=NAMING_CONVENTION)

# 进程安全的DatabaseManager（适配多Worker）
class DatabaseManager:
    def __init__(self, process_id: int):
        self.process_id = process_id
        # 读写分离引擎
        self._write_engine: Optional[AsyncEngine] = None
        self._read_engines: List[AsyncEngine] = []
        self._write_session_factory: Optional[async_sessionmaker[AsyncSession]] = None
        self._read_session_factories: List[async_sessionmaker[AsyncSession]] = []
        self._init_lock = asyncio.Lock()
        self._initialized = False

    async def init(self):
        async with self._init_lock:
            if self._initialized:
                return
            # 通用引擎配置（生产级优化）
            engine_kwargs = {
                "poolclass": QueuePool,
                "pool_size": settings.DB_POOL_SIZE,
                "max_overflow": settings.DB_MAX_OVERFLOW,
                "pool_recycle": settings.DB_POOL_RECYCLE,
                "pool_pre_ping": settings.DB_POOL_PRE_PING,
                "pool_use_lifo": True,  # 高并发下LIFO更优
                "echo": False,  # 生产环境关闭SQL打印
                "connect_args": {
                    "connect_timeout": 10,
                    "server_settings": {"application_name": f"fastapi-{self.process_id}"}
                }
            }
            # 初始化写引擎
            self._write_engine = create_async_engine(settings.DB_WRITE_DSN, **engine_kwargs)
            self._write_session_factory = async_sessionmaker(
                bind=self._write_engine, class_=AsyncSession,
                expire_on_commit=False, autoflush=False, autocommit=False
            )
            # 初始化读引擎（读写分离）
            if settings.DB_ENABLE_RW_SEPARATION and settings.DB_READ_DSNS:
                for dsn in settings.DB_READ_DSNS:
                    read_engine = create_async_engine(dsn, **engine_kwargs)
                    self._read_engines.append(read_engine)
                    self._read_session_factories.append(
                        async_sessionmaker(bind=read_engine, class_=AsyncSession, expire_on_commit=False)
                    )
            self._initialized = True
            logger.info(f"DB manager initialized (process: {self.process_id})")

    async def get_session(self, read_only: bool = False) -> AsyncGenerator[AsyncSession, None]:
        if not self._initialized:
            raise RuntimeError("DB manager not initialized")
        # 读库选择（轮询+故障跳过）
        if read_only and self._read_session_factories:
            idx = hash(asyncio.current_task().get_name()) % len(self._read_session_factories)
            session_factory = self._read_session_factories[idx]
        else:
            session_factory = self._write_session_factory
        async with session_factory() as session:
            yield session

    async def close(self):
        async with self._init_lock:
            if not self._initialized:
                return
            if self._write_engine:
                await self._write_engine.dispose()
            for eng in self._read_engines:
                await eng.dispose()
            self._initialized = False

# 进程安全单例工厂
@lru_cache(maxsize=None)
def get_db_manager() -> DatabaseManager:
    return DatabaseManager(process_id=os.getpid())

# FastAPI依赖注入（读写分离）
async def get_async_session(read_only: bool = False) -> AsyncGenerator[AsyncSession, None]:
    manager = get_db_manager()
    async for session in manager.get_session(read_only=read_only):
        yield session

# 只读/只写依赖
async def get_read_db() -> AsyncGenerator[AsyncSession, None]:
    async for session in get_async_session(read_only=True):
        yield session

async def get_write_db() -> AsyncGenerator[AsyncSession, None]:
    async for session in get_async_session(read_only=False):
        yield session

# 应用启动/关闭钩子
async def startup_db():
    await get_db_manager().init()

async def shutdown_db():
    await get_db_manager().close()
