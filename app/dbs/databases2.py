# -*- coding: utf-8 -*-
import asyncio
import os
import structlog
from functools import lru_cache, wraps
from typing import AsyncGenerator, Optional, List, Dict, Any

from sqlalchemy import MetaData, text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker, AsyncEngine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import QueuePool
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from functools import wraps
from app.config import settings

# ========== 基础配置 ==========
logger = structlog.get_logger("db_manager")

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

# ========== 进程安全的DatabaseManager ==========
class DatabaseManager:
    def __init__(self, process_id: int):
        self.process_id = process_id
        # 多主库（主库+备用）
        self._write_engines: List[AsyncEngine] = []
        self._write_session_factories: List[async_sessionmaker[AsyncSession]] = []
        self._current_write_idx = 0
        # 多从库
        self._read_engines: List[AsyncEngine] = []
        self._read_session_factories: List[async_sessionmaker[AsyncSession]] = []
        # 线程安全锁
        self._init_lock = asyncio.Lock()
        self._initialized = False

    # 从库延迟问题处理（关键避坑）
    async def _get_slave_delay(self, engine: AsyncEngine) -> float:
        """获取从库延迟（秒），仅PostgreSQL示例"""
        try:
            async with engine.connect() as conn:
                # 查询主从延迟（需根据数据库类型调整SQL）
                result = await conn.execute(text("""
                    SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp())) AS delay;
                """))
                delay = result.scalar() or 0.0
                return float(delay)
        except Exception:
            return float("inf")  # 异常时视为延迟无限大

    async def init(self):
        async with self._init_lock:
            if self._initialized:
                logger.warning(f"Process {self.process_id}: DB manager already initialized")
                return

            engine_kwargs = {
                "poolclass": QueuePool,
                "pool_size": settings.db_pool_size,
                "max_overflow": settings.db_max_overflow,
                "pool_recycle": settings.db_pool_recycle,
                "pool_pre_ping": True,
                "pool_use_lifo": settings.db_pool_use_lifo,  # 配置化LIFO/FIFO
                "echo": settings.db_echo,
                "connect_args": {
                    "connect_timeout": settings.db_connect_timeout,
                    "charset": settings.db_charset,
                    "server_settings": {"application_name": f"fastapi-{self.process_id}"}
                }
            }

            # 1. 初始化多主库
            if not settings.db_write_dsns:
                raise ValueError("No write DSNs configured")
            for idx, dsn in enumerate(settings.db_write_dsns):
                try:
                    engine = create_async_engine(dsn, **engine_kwargs)
                    self._write_engines.append(engine)
                    self._write_session_factories.append(
                        async_sessionmaker(
                            bind=engine, class_=AsyncSession,
                            expire_on_commit=False, autoflush=False, autocommit=False
                        )
                    )
                    logger.info(f"Process {self.process_id}: Write engine {idx} initialized (DSN: {dsn[:20]}...)")
                except Exception as e:
                    logger.error(f"Process {self.process_id}: Failed to init write engine {idx}", error=str(e))

            # 2. 初始化多从库
            if settings.db_enable_rw_separation and settings.db_read_dsns:
                for idx, dsn in enumerate(settings.db_read_dsns):
                    try:
                        engine = create_async_engine(dsn, **engine_kwargs)
                        self._read_engines.append(engine)
                        self._read_session_factories.append(
                            async_sessionmaker(
                                bind=engine, class_=AsyncSession,
                                expire_on_commit=False, autoflush=False, autocommit=False
                            )
                        )
                        logger.info(f"Process {self.process_id}: Read engine {idx} initialized (DSN: {dsn[:20]}...)")
                    except Exception as e:
                        logger.error(f"Process {self.process_id}: Failed to init read engine {idx}", error=str(e))

            self._initialized = True
            logger.info(f"Process {self.process_id}: DB manager initialized (write: {len(self._write_engines)}, read: {len(self._read_engines)})")

    async def _switch_write_engine(self):
        """主库故障切换到备用主库"""
        async with self._init_lock:
            old_idx = self._current_write_idx
            self._current_write_idx = (self._current_write_idx + 1) % len(self._write_engines)
            logger.warning(f"Process {self.process_id}: Switched write engine from {old_idx} to {self._current_write_idx}")

    async def _check_engine_health(self, engine: AsyncEngine) -> bool:
        """检查引擎健康状态"""
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            return True
        except Exception:
            return False

    async def get_session(self, read_only: bool = False) -> AsyncGenerator[AsyncSession, None]:
        if not self._initialized:
            raise RuntimeError(f"Process {self.process_id}: DB manager not initialized")

        # 写会话（带故障切换）
        if not read_only:
            max_retries = len(self._write_engines)
            for _ in range(max_retries):
                current_idx = self._current_write_idx
                try:
                    session_factory = self._write_session_factories[current_idx]
                    async with session_factory() as session:
                        yield session
                        return
                except Exception as e:
                    logger.error(f"Process {self.process_id}: Write engine {current_idx} failed", error=str(e))
                    await self._switch_write_engine()
            raise RuntimeError(f"Process {self.process_id}: All write engines are unavailable")

        # 读会话（轮询+故障跳过）
        if self._read_session_factories:
            idx = hash(asyncio.current_task().get_name()) % len(self._read_session_factories)            
            # 跳过故障的读引擎
            for _ in range(len(self._read_session_factories)):
                if await self._check_engine_health(self._read_engines[idx]):
                    delay = await self._get_slave_delay(self._read_engines[idx])
                    if delay > settings.db_slave_delay_threshold:
                        logger.warning(f"Slave engine {idx} delay {delay}s > threshold {settings.db_slave_delay_threshold}s, switch to master")
                        read_only = False  # 切主库
                        session_factory = self._write_session_factories[current_idx]
                    else:
                        session_factory = self._read_session_factories[idx]
                    async with session_factory() as session:
                        yield session
                        return
                idx = (idx + 1) % len(self._read_session_factories)
            raise RuntimeError(f"Process {self.process_id}: All read engines are unavailable")

        # 无读库时使用写库
        async for session in self.get_session(read_only=False):
            yield session

    async def get_session_for_transaction(self) -> AsyncGenerator[AsyncSession, None]:
        """
        事务专用会话（强制走主库，禁用自动提交）
        用于混合读写的事务场景
        """
        async for session in self.get_session(read_only=False):
            # 事务内禁用自动刷新，提升性能
            session.autoflush = False
            yield session

    async def get_session_for_write_then_read(self) -> AsyncGenerator[AsyncSession, None]:
        """
        写后立即读专用会话（强制走主库）
        用于非事务场景下“写→读”的依赖操作
        """
        async for session in self.get_session(read_only=False):
            yield session

    def get_pool_status(self) -> Dict[str, Any]:
        if not self._initialized:
            return {"status": "uninitialized", "process_id": self.process_id}
        return {
            "process_id": self.process_id,
            "current_write_idx": self._current_write_idx,
            "write_pools": [self._get_engine_pool_status(eng) for eng in self._write_engines],
            "read_pools": [self._get_engine_pool_status(eng) for eng in self._read_engines],
        }

    @staticmethod
    def _get_engine_pool_status(engine: AsyncEngine) -> Dict[str, int]:
        pool = engine.pool
        return {
            "pool_size": pool.size(),
            "checked_out": pool.checkedout(),
            "overflow": pool.overflow(),
            "recycle": pool.recycle,
            "pre_ping": pool._pre_ping
        }

    async def health_check(self) -> Dict[str, Any]:
        if not self._initialized:
            return {"status": "unhealthy", "process_id": self.process_id, "reason": "not initialized"}

        write_healthy = await self._check_engine_health(self._write_engines[self._current_write_idx])
        read_healthy = True
        if self._read_engines:
            read_healthy = all([await self._check_engine_health(eng) for eng in self._read_engines])

        overall_status = "healthy" if write_healthy and (read_healthy or not self._read_engines) else "unhealthy"
        return {
            "status": overall_status,
            "process_id": self.process_id,
            "write_healthy": write_healthy,
            "read_healthy": read_healthy,
            "pool_status": self.get_pool_status(),
        }

    async def close(self):
        async with self._init_lock:
            if not self._initialized:
                return

            # 关闭写引擎
            for idx, eng in enumerate(self._write_engines):
                try:
                    await eng.dispose()
                    logger.info(f"Process {self.process_id}: Write engine {idx} disposed")
                except Exception as e:
                    logger.error(f"Process {self.process_id}: Failed to dispose write engine {idx}", error=str(e))

            # 关闭读引擎
            for idx, eng in enumerate(self._read_engines):
                try:
                    await eng.dispose()
                    logger.info(f"Process {self.process_id}: Read engine {idx} disposed")
                except Exception as e:
                    logger.error(f"Process {self.process_id}: Failed to dispose read engine {idx}", error=str(e))

            self._initialized = False
            logger.info(f"Process {self.process_id}: DB manager closed")

# ========== 进程安全单例工厂 ==========
@lru_cache(maxsize=None)
def get_db_manager() -> DatabaseManager:
    """每个进程仅创建一个DatabaseManager实例"""
    process_id = os.getpid()
    manager = DatabaseManager(process_id=process_id)
    logger.info(f"Created DB manager for process {process_id}")
    return manager

# 全局实例（进程安全）
db_manager = get_db_manager()

# ========== 重试装饰器 & 生命周期函数 ==========
def db_retry_decorator(max_attempts: int = 3):
    def decorator(func):
        @retry(
            stop=stop_after_attempt(max_attempts),
            wait=wait_exponential(multiplier=1, min=1, max=5),
            retry=retry_if_exception_type((asyncio.TimeoutError, ConnectionRefusedError, RuntimeError)),
            reraise=True
        )
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                logger.error(f"DB operation failed (retrying)", func=func.__name__, error=str(e))
                raise
        return wrapper
    return decorator

async def init_db_schema():
    if not db_manager._initialized:
        raise RuntimeError("DB manager not initialized")
    try:
        # 使用当前主库初始化表结构
        async with db_manager._write_engines[db_manager._current_write_idx].begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info(f"Process {db_manager.process_id}: DB schema initialized")
    except Exception as e:
        logger.error(f"Process {db_manager.process_id}: Failed to init DB schema", error=str(e))
        raise

async def startup_db():
    await db_manager.init()
    if settings.env == "development":
        await init_db_schema()
    health = await db_manager.health_check()
    if health["status"] != "healthy":
        raise RuntimeError(f"Process {db_manager.process_id}: DB health check failed: {health}")

async def shutdown_db():
    await db_manager.close()

# ========== 依赖注入 ==========
async def get_db(read_only: bool = False) -> AsyncGenerator[AsyncSession, None]:
    async for session in db_manager.get_session(read_only=read_only):
        yield session

async def get_read_db() -> AsyncGenerator[AsyncSession, None]:
    async for session in get_db(read_only=True):
        yield session

async def get_write_db() -> AsyncGenerator[AsyncSession, None]:
    async for session in get_db(read_only=False):
        yield session

# 测试环境依赖（独立实例）
async def get_test_db(read_only: bool = False) -> AsyncGenerator[AsyncSession, None]:
    test_manager = DatabaseManager(process_id=os.getpid())
    await test_manager.init()
    async for session in test_manager.get_session(read_only=read_only):
        yield session
    await test_manager.close()


####
# 进阶优化：自动适配读写分离（减少开发成本）
from functools import wraps
from sqlalchemy.ext.asyncio import AsyncSession

def auto_rw_separation(func):
    """
    自动读写分离装饰器：
    - 方法内有写操作→强制主库
    - 纯读操作→从库
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # 提取db会话参数
        db_param = None
        for arg in args:
            if isinstance(arg, AsyncSession):
                db_param = arg
                break
        if not db_param:
            for k, v in kwargs.items():
                if isinstance(v, AsyncSession):
                    db_param = v
                    break

        if db_param:
            # 检测方法内是否有写操作（简化版：可根据SQLAlchemy事件扩展）
            has_write_operation = any(
                [hasattr(db_param, "_write_ops"), db_param.new, db_param.dirty, db_param.deleted]
            )
            if has_write_operation:
                # 有写操作→强制主库
                kwargs["read_only"] = False
            else:
                # 纯读→从库
                kwargs["read_only"] = True

        return await func(*args, **kwargs)
    return wrapper

#### 以下是制动切换demo 自动切换的依赖注入
async def get_auto_rw_db() -> AsyncGenerator[AsyncSession, None]:
    """自动切换主/从库的会话依赖"""
    # 初始默认读从库，有写操作时自动切主库
    async for session in db_manager.get_session(read_only=True):
        yield session

@auto_rw_separation
async def mixed_operation(
    product_id: int,
    db: AsyncSession = Depends(get_auto_rw_db)
):
    """自动适配读写分离的混合操作"""
    # 1. 纯读→从库
    product = await db.execute(select(Product).where(Product.id == product_id))
    product = product.scalar_one()

    # 2. 写操作→自动切主库
    product.stock += 10
    await db.commit()

    # 3. 写后读→主库
    updated_product = await db.execute(select(Product).where(Product.id == product_id))
    return updated_product.scalar_one()

