# -*- coding: utf-8 -*-

import os
import time
import asyncio
from app.core.config import settings
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import QueuePool
from typing import AsyncGenerator, Optional, List, Dict, Any
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker, AsyncEngine
from functools import lru_cache, wraps
from sqlalchemy import MetaData, text
import orjson
import random
from app.core.logger import setup_strcutlogger

logger = setup_strcutlogger()

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
        self._slave_delays: List[float] = []
        self._delay_refresh_task: Optional[asyncio.Task] = None
        # 线程安全锁
        self._init_lock = asyncio.Lock()
        self._initialized = False

    async def init(self):
        async with self._init_lock:
            if self._initialized:
                logger.warning(f"Process {self.process_id}: DB manager already initialized")
                return
            
            engine_kwargs = {
                "poolclass": QueuePool,
                "pool_size": settings.DB_POOL_SIZE,
                "max_overflow": settings.DB_MAX_OVERFLOW,
                "pool_recycle": settings.DB_POOL_RECYCLE,
                "pool_timeout": settings.DB_POOL_TIMEOUT,
                "pool_pre_ping": settings.DB_PRE_PING,
                "pool_use_lifo": settings.DB_POOL_USE_LIFO,
                "echo": settings.DB_ECHO,
                "echo_pool": False,  # 关闭连接池日志
                "future": True, # 启用 SQLAlchemy 2.0 模式
                # "json_serializer": orjson.dumps,  # 如果用 JSON 字段
                "json_serializer": lambda obj: orjson.dumps(obj).decode(),
                "json_deserializer": orjson.loads,
                "connect_args": {
                    "server_settings": {
                        "application_name": settings.APP_NAME,
                        "timezone": "UTC",
                        "charset": "utf8mb4",
                    }
                },
            }

            # 1. 初始化多主库
            if not settings.db_write_dsns:
                raise ValueError("No write DSNs configured")
            for idx, dsn in enumerate(settings.DB_WRITE_DSN):
                try:
                    engine = create_async_engine(dsn, **engine_kwargs)
                    self._write_engines.append(engine)
                    self._write_session_factories.append(
                        async_sessionmaker(
                            bind=engine, class_=AsyncSession,
                            expire_on_commit=False, autoflush=False, autocommit=False
                        )
                    )
                    logger.info(
                        f"Process {self.process_id}: Write engine {idx} initialized (DSN: {dsn[:20]}...)",
                        host=dsn
                    )
                except Exception as e:
                    logger.error(f"Process {self.process_id}: Failed to init write engine {idx}", error=str(e))

            # 2. 初始化多从库
            if settings.DB_ENABLE_RW_SEPARATION and settings.D1800B_READ_DSNS:
                for idx, dsn in enumerate(settings.DB_READ_DSNS):
                    try:
                        engine = create_async_engine(dsn, **engine_kwargs)
                        self._read_engines.append(engine)
                        self._read_session_factories.append(
                            async_sessionmaker(
                                bind=engine, class_=AsyncSession,
                                expire_on_commit=False, autoflush=False, autocommit=False
                            )
                        )
                        logger.info(
                            f"Process {self.process_id}: Read engine {idx} initialized (DSN: {dsn[:20]}...)",
                            host=dsn
                        )
                    except Exception as e:
                        logger.error(f"Process {self.process_id}: Failed to init read engine {idx}", error=str(e))
                    
                    if self._read_engines:
                        self._slave_delays = [float("inf")] * len(self._read_engines)
                        self._delay_refresh_task = asyncio.create_task(self._refresh_slave_delays())

            self._initialized = True
            logger.info(f"Process {self.process_id}: DB manager initialized (write: {len(self._write_engines)}, read: {len(self._read_engines)})")

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

    async def _refresh_slave_delays(self):
        """后台任务：每 180 秒刷新一次从库延迟"""
        while self._initialized:
            try:
                for idx, engine in enumerate(self._read_engines):
                    delay = await self._get_slave_delay(engine)
                    if delay > settings.DB_SLAVE_DELAY_THRESHOLD:
                        logger.warning(f"Slave engine {idx} delay {delay}s > threshold {settings.DB_SLAVE_DELAY_THRESHOLD}s")
                    self._slave_delays[idx] = delay
                await asyncio.sleep(180)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning("Failed to refresh slave delays", error=str(e))
                await asyncio.sleep(1)

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
                write_ping = await conn.execute(text("SELECT 1"))
                write_ok = write_ping.scalar() == 1
            return write_ok
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
        
        # # 读会话（轮询+故障跳过）
        # if self._read_session_factories:
        #     idx: int = hash(asyncio.current_task().get_name()) % len(self._read_session_factories)
        #     for _ in range(len(self._read_session_factories)):
        #         if await self._check_engine_health(self._read_engines[idx]):
        #             delay = self._slave_delays[idx]
        #             if delay > settings.DB_SLAVE_DELAY_THRESHOLD:
        #                 logger.warning(f"Slave engine {idx} delay {delay}s > threshold {settings.DB_SLAVE_DELAY_THRESHOLD}s, switch to master")
        #                 read_only = False  # 切主库
        #                 session_factory = self._write_session_factories[current_idx]
        #             else:
        #                 session_factory = self._read_session_factories[idx]
        #             async with session_factory() as session:
        #                 yield session
        #                 return
        #         idx = (idx + 1) % len(self._read_session_factories)
        #     raise RuntimeError(f"Process {self.process_id}: All read engines are unavailable")
        if self._read_session_factories:
            read_only = False
            async with self._get_best_read_session() as session:
                yield session
                return

    async def _get_best_read_session(self) -> async_sessionmaker[AsyncSession]:
        """选择最优的从库会话工厂"""
        if not self._read_session_factories:
            logger.warning(f"No read engine {idx}, switch to master")
            return self._write_session_factories[self._current_write_idx]

        candidates = []
        for idx, engine in enumerate(self._read_engines):
            if not await self._check_engine_health(engine):
                continue
            delay = await self._slave_delays(engine)
            # 计算权重：延迟越低，权重越高（示例算法，可调整）
            if delay < settings.DB_SLAVE_DELAY_THRESHOLD:
                # 假设权重与延迟成反比，并考虑一个基础权重
                weight = max(1, int(100 / (delay + 1)))  # 避免除零
                candidates.append((weight, idx))

        if not candidates:
            # 无健康从库，降级到主库
            logger.warning(f"No healthy slave engines, maybe all delayed {delay}s > threshold {settings.DB_SLAVE_DELAY_THRESHOLD}s, switch to master")
            return self._write_session_factories[self._current_write_idx]

        # 根据权重随机选择
        weights, indices = zip(*candidates)
        chosen_idx = random.choices(indices, weights=weights, k=1)[0]
        return self._read_session_factories[chosen_idx]

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
    
    async def close(self, timeout: int = 30):
        async with self._init_lock:
            if not self._initialized:
                return

            # 关闭写引擎
            start_time = time.time()
            for idx, eng in enumerate(self._write_engines):
                while eng.pool.checkedout() > 0 and (time.time() - start_time) < timeout:
                    await asyncio.sleep(0.1)
                if eng.pool.checkedout() > 0:
                    logger.warning(f"Force closing write engine {idx} with {eng.pool.checkedout()} active connections")
                try:
                    await eng.dispose()
                    logger.info(f"Process {self.process_id}: Write engine {idx} disposed")
                except Exception as e:
                    logger.error(f"Process {self.process_id}: Failed to dispose write engine {idx}", error=str(e))

            # 关闭读引擎
            start_time = time.time()
            for idx, eng in enumerate(self._read_engines):
                while eng.pool.checkedout() > 0 and (time.time() - start_time) < timeout:
                    await asyncio.sleep(0.1)
                if eng.pool.checkedout() > 0:
                    logger.warning(f"Force closing read engine {idx} with {eng.pool.checkedout()} active connections")
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
            stop=stop_after_attempt(settings.DB_RETRY_MAX_ATTEMPTS),
            wait=wait_exponential(
                multiplier=settings.DB_RETRY_DELAY,
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
        @wraps(func)
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except Exception as e:
                logger.error(
                    f"DB operation failed (retrying)", 
                    func=func.__name__, 
                    error=str(e)
                )
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

async def db_health_check():
    if not db_manager._initialized:
        raise RuntimeError("DB manager not initialized")
    health = await db_manager.health_check()
    if health["status"] != "healthy":
        raise RuntimeError(f"Process {db_manager.process_id}: DB health check failed: {health}")
    return health

async def startup_db():
    if not db_manager._initialized:
        raise RuntimeError("DB manager not initialized")
    await db_manager.init()
    if settings.ENV == "dev":
        await init_db_schema()
    health = await db_health_check()
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

# @auto_rw_separation
# async def mixed_operation(
#     product_id: int,
#     db: AsyncSession = Depends(get_auto_rw_db)
# ):
#     """自动适配读写分离的混合操作"""
#     # 1. 纯读→从库
#     product = await db.execute(select(Product).where(Product.id == product_id))
#     product = product.scalar_one()

#     # 2. 写操作→自动切主库
#     product.stock += 10
#     await db.commit()

#     # 3. 写后读→主库
#     updated_product = await db.execute(select(Product).where(Product.id == product_id))
#     return updated_product.scalar_one()