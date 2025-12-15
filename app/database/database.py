# -*- coding: utf-8 -*-

from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import sessionmaker, DeclarativeBase
from typing import AsyncGenerator
from app.core.config import settings
import asyncio
from contextlib import asynccontextmanager
from sqlalchemy import MetaData

class Base(DeclarativeBase):
    """SQLAlchemy 基础模型"""
    pass

class DatabaseManager:
    """高性能数据库管理器"""
    
    def __init__(self):
        self._engine = None
        self._session_factory = None
    
    def init(self):
        """初始化数据库连接"""
        # 创建异步引擎
        self._engine = create_async_engine(
            settings.db_jdbcurl,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_recycle=settings.db_pool_recycle,
            echo=settings.db_echo,
            pool_pre_ping=True,
            pool_use_lifo=False,
            connect_args={"connect_timeout": 10, "charset": "utf8mb4"}
        )               
        
        # 创建会话工厂
        self._session_factory = async_sessionmaker(
            bind=self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
            autocommit=False
        )
    
    async def close(self):
        """关闭数据库连接"""
        if self._engine:
            await self._engine.dispose()
    
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """获取数据库会话"""
        if not self._session_factory:
            raise Exception("Database not initialized")
        
        async with self._session_factory() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()
    
    @property
    def session_factory(self):
        """获取会话工厂"""
        return self._session_factory

# 全局数据库管理器实例
db_manager = DatabaseManager()

async def init_db():
    """初始化数据库"""
    async with db_manager._engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """数据库依赖注入"""
    async for session in db_manager.get_session():
        yield session

# 初始化数据库
async def startup_db():
    """应用启动时初始化数据库"""
    db_manager.init()
    await init_db()

async def shutdown_db():
    """应用关闭时清理数据库连接"""
    await db_manager.close()