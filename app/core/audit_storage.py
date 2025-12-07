# -*- coding: utf-8 -*-
# doubao

import os 
from typing import List, Dict, Any, Optional
import asyncio
from redis.asyncio import Redis, RedisCluster, RedisError
import asyncpg
import orjson
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from app.core.audit_log import sign_audit_log
from app.core.logger import audit_logger
from app.core.config import settings
from uuid_extensions import uuid7

# ========== 存储抽象基类 ==========
class AuditStorage:
    """审计日志存储基类"""
    async def init(self):
        """初始化存储连接"""
        pass

    async def write(self, log_data: Dict[str, Any]):
        """写入单条日志"""
        pass

    async def batch_write(self, logs: List[Dict[str, Any]]):
        """批量写入日志"""
        pass

    async def close(self):
        """关闭连接"""
        pass

# ========== Redis存储（热数据/批量缓存） ==========
class RedisAuditStorage(AuditStorage):
    def __init__(self):
        self.redis: Optional[Redis] = None
        self.batch_queue: List[Dict[str, Any]] = []
        self.batch_lock = asyncio.Lock()
        self.batch_task: Optional[asyncio.Task] = None

    async def init(self):
        """初始化Redis连接"""
        self.redis = Redis.from_url(
            settings.REDIS_URL,
            encoding="utf-8",
            decode_responses=False,
        )
        # 启动批量写入任务
        if settings.AUDIT_LOG_BATCH_ENABLE:
            self.batch_task = asyncio.create_task(self.batch_worker())
        audit_logger.info("Redis audit storage initialized")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=5),
        retry=retry_if_exception_type((RedisError, asyncio.TimeoutError)),
        reraise=True,
    )
    async def write(self, log_data: Dict[str, Any]):
        """异步写入Redis（批量/单条）"""
        if settings.AUDIT_LOG_BATCH_ENABLE:
            async with self.batch_lock:
                self.batch_queue.append(log_data)
                # 达到批量阈值则立即触发写入
                if len(self.batch_queue) >= settings.AUDIT_LOG_BATCH_SIZE:
                    await self._flush_batch()
        else:
            # 单条写入
            log_data["signature"] = sign_audit_log(log_data)
            await self.redis.rpush(
                settings.REDIS_AUDIT_KEY,
                orjson.dumps(log_data, default=str).encode()
            )

    async def batch_write(self, logs: List[Dict[str, Any]]):
        """批量写入Redis"""
        if not logs or not self.redis:
            return
        
        # 签名所有日志
        for log in logs:
            log["signature"] = sign_audit_log(log)
        
        # 批量写入
        await self.redis.rpush(
            settings.AUDIT_LOG_REDIS_KEY,
            *[orjson.dumps(log, default=str).encode() for log in logs]
        )
        audit_logger.info("Batch logs written to Redis", count=len(logs))

    async def batch_worker(self):
        """批量写入工作线程（定时+阈值）"""
        while True:
            try:
                await asyncio.sleep(settings.AUDIT_LOG_BATCH_INTERVAL)
                async with self.batch_lock:
                    if self.batch_queue:
                        await self.batch_write(self.batch_queue)
                        self.batch_queue = []
            except Exception as e:
                audit_logger.error("Redis batch worker error", error=str(e))
                continue

    async def _flush_batch(self):
        """刷入批量队列"""
        if not self.batch_queue:
            return
        logs = self.batch_queue.copy()
        self.batch_queue = []
        await self.batch_write(logs)

    async def close(self):
        """关闭Redis连接"""
        if self.batch_task:
            self.batch_task.cancel()
            try:
                await self.batch_task
            except asyncio.CancelledError:
                pass
        # 刷入剩余队列
        async with self.batch_lock:
            await self._flush_batch()
        if self.redis:
            await self.redis.close()
        audit_logger.info("Redis audit storage closed")

# ========== PostgreSQL存储（持久化） ==========
class PostgresAuditStorage(AuditStorage):
    def __init__(self):
        self.pool: Optional[asyncpg.Pool] = None

    async def init(self):
        """初始化PostgreSQL连接池"""
        # 从环境变量获取PostgreSQL配置（复用数据库配置）
        self.pool = await asyncpg.create_pool(
            user=os.getenv("POSTGRES_USER", "postgres"),
            password=os.getenv("POSTGRES_PASSWORD", "postgresAdmin"),
            host=os.getenv("POSTGRES_HOST", "localhost"),
            port=int(os.getenv("POSTGRES_PORT", 5432)),
            database=os.getenv("POSTGRES_DB", "fastxai"),
            min_size=5,
            max_size=20,
            command_timeout=30,
        )
        # 创建审计日志表（首次初始化）
        await self._create_audit_table()
        audit_logger.info("PostgreSQL audit storage initialized")
    
    async def _create_audit_table(self):
        """创建审计日志表（企业级结构）"""
        create_sql = f"""
        CREATE TABLE IF NOT EXISTS {settings.POSTGRES_AUDIT_TABLE} (
            audit_id UUID PRIMARY KEY,
            timestamp TIMESTAMPTZ NOT NULL,
            user_id UUID,
            user_name VARCHAR(100),
            operation VARCHAR(50) NOT NULL,
            resource_type VARCHAR(50) NOT NULL,
            resource_id UUID,
            request_ip VARCHAR(50) NOT NULL,
            request_method VARCHAR(10) NOT NULL,
            request_path VARCHAR(255) NOT NULL,
            request_params JSONB,
            request_body JSONB,
            response_status INT NOT NULL,
            response_time FLOAT,
            status VARCHAR(20) NOT NULL,  -- success/failed
            error_msg TEXT,
            signature VARCHAR(64),
            app_name VARCHAR(50) NOT NULL,
            environment VARCHAR(20) NOT NULL,
            created_at TIMESTAMPTZ DEFAULT NOW()
        );
        -- 创建索引（优化查询性能）
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON {settings.POSTGRES_AUDIT_TABLE}(timestamp);
        CREATE INDEX IF NOT EXISTS idx_audit_user_id ON {settings.POSTGRES_AUDIT_TABLE}(user_id);
        CREATE INDEX IF NOT EXISTS idx_audit_resource ON {settings.POSTGRES_AUDIT_TABLE}(resource_type, resource_id);
        CREATE INDEX IF NOT EXISTS idx_audit_operation ON {settings.POSTGRES_AUDIT_TABLE}(operation);
        """
        async with self.pool.acquire() as conn:
            await conn.execute(create_sql)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=5),
        retry=retry_if_exception_type((asyncpg.PostgresError, asyncio.TimeoutError)),
        reraise=True,
    )
    async def write(self, log_data: Dict[str, Any]):
        """写入单条日志到PostgreSQL"""
        if not self.pool:
            return
        
        # 签名日志
        log_data["signature"] = sign_audit_log(log_data)
        
        # 插入SQL
        insert_sql = f"""
        INSERT INTO {settings.POSTGRES_AUDIT_TABLE} (
            audit_id, timestamp, user_id, user_name, operation, resource_type,
            resource_id, request_ip, request_method, request_path, request_params,
            request_body, response_status, response_time, status, error_msg,
            signature, app_name, environment
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19
        )
        """
        async with self.pool.acquire() as conn:
            await conn.execute(
                insert_sql,
                log_data.get("audit_id"),
                log_data.get("timestamp"),
                log_data.get("user_id"),
                log_data.get("user_name"),
                log_data.get("operation"),
                log_data.get("resource_type"),
                log_data.get("resource_id"),
                log_data.get("request_ip"),
                log_data.get("request_method"),
                log_data.get("request_path"),
                log_data.get("request_params"),
                log_data.get("request_body"),
                log_data.get("response_status"),
                log_data.get("response_time"),
                log_data.get("status"),
                log_data.get("error_msg"),
                log_data.get("signature"),
                settings.APP_NAME,
                settings.ENVIRONMENT,
            )

    async def batch_write(self, logs: List[Dict[str, Any]]):
        """批量写入PostgreSQL（高性能）"""
        if not logs or not self.pool:
            return sign_audit_log
        
        # 准备批量数据
        batch_data = []
        for log in logs:
            log["signature"] = sign_audit_log(log)
            batch_data.append((
                log.get("audit_id"),
                log.get("timestamp"),
                log.get("user_id"),
                log.get("user_name"),
                log.get("operation"),
                log.get("resource_type"),
                log.get("resource_id"),
                log.get("request_ip"),
                log.get("request_method"),
                log.get("request_path"),
                log.get("request_params"),
                log.get("request_body"),
                log.get("response_status"),
                log.get("response_time"),
                log.get("status"),
                log.get("error_msg"),
                log.get("signature"),
                settings.APP_NAME,
                settings.ENVIRONMENT,
            ))
        
        # 批量插入
        async with self.pool.acquire() as conn:
            await conn.executemany(
                f"""
                INSERT INTO {settings.POSTGRES_AUDIT_TABLE} (
                    audit_id, timestamp, user_id, user_name, operation, resource_type,
                    resource_id, request_ip, request_method, request_path, request_params,
                    request_body, response_status, response_time, status, error_msg,
                    signature, app_name, environment
                ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
                """,
                batch_data
            )
        audit_logger.info("Batch logs written to PostgreSQL", count=len(logs))

    async def close(self):
        """关闭PostgreSQL连接池"""
        if self.pool:
            await self.pool.close()
        audit_logger.info("PostgreSQL audit storage closed")

# # ========== ES存储（可选，检索优化） ==========
# class ESAuditStorage(AuditStorage):
#     def __init__(self):
#         self.es: Optional[AsyncElasticsearch] = None

#     async def init(self):
#         """初始化ES连接"""
#         self.es = AsyncElasticsearch([audit_settings.ES_URL])
#         # 创建索引（如果不存在）
#         await self._create_es_index()
#         audit_logger.info("ES audit storage initialized")

#     async def _create_es_index(self):
#         """创建ES索引（结构化+分词）"""
#         index_settings = {
#             "settings": {
#                 "number_of_shards": 3,
#                 "number_of_replicas": 1,
#                 "refresh_interval": "5s"  # 性能优化：5秒刷新
#             },
#             "mappings": {
#                 "properties": {
#                     "audit_id": {"type": "keyword"},
#                     "timestamp": {"type": "date"},
#                     "user_id": {"type": "keyword"},
#                     "user_name": {"type": "keyword"},
#                     "operation": {"type": "keyword"},
#                     "resource_type": {"type": "keyword"},
#                     "resource_id": {"type": "keyword"},
#                     "request_ip": {"type": "ip"},
#                     "request_method": {"type": "keyword"},
#                     "request_path": {"type": "keyword"},
#                     "request_params": {"type": "object"},
#                     "request_body": {"type": "object"},
#                     "response_status": {"type": "integer"},
#                     "response_time": {"type": "float"},
#                     "status": {"type": "keyword"},
#                     "error_msg": {"type": "text"},
#                     "signature": {"type": "keyword"},
#                     "app_name": {"type": "keyword"},
#                     "environment": {"type": "keyword"},
#                 }
#             }
#         }
#         if not await self.es.indices.exists(index=audit_settings.ES_AUDIT_INDEX):
#             await self.es.indices.create(
#                 index=audit_settings.ES_AUDIT_INDEX,
#                 body=index_settings
#             )

#     @retry(
#         stop=stop_after_attempt(3),
#         wait=wait_exponential(multiplier=1, min=1, max=5),
#         retry=retry_if_exception_type((Exception,)),
#         reraise=True,
#     )
#     async def write(self, log_data: Dict[str, Any]):
#         """写入单条日志到ES"""
#         if not self.es:
#             return
        
#         log_data["signature"] = sign_audit_log(log_data)
#         await self.es.index(
#             index=audit_settings.ES_AUDIT_INDEX,
#             id=log_data["audit_id"],
#             body=log_data
#         )

#     async def batch_write(self, logs: List[Dict[str, Any]]):
#         """批量写入ES"""
#         if not logs or not self.es:
#             return
        
#         bulk_operations = []
#         for log in logs:
#             log["signature"] = sign_audit_log(log)
#             bulk_operations.append({
#                 "index": {
#                     "_index": audit_settings.ES_AUDIT_INDEX,
#                     "_id": log["audit_id"]
#                 }
#             })
#             bulk_operations.append(log)
        
#         await self.es.bulk(body=bulk_operations)
#         audit_logger.info("Batch logs written to ES", count=len(logs))

#     async def close(self):
#         """关闭ES连接"""
#         if self.es:
#             await self.es.close()
#         audit_logger.info("ES audit storage closed")

# ========== 多存储聚合服务 ==========
class AuditLogService:
    """审计日志聚合存储服务"""
    def __init__(self):
        self.storages: List[AuditStorage] = []
        self.init_lock = asyncio.Lock()

    async def init(self):
        """初始化所有存储后端"""
        async with self.init_lock:
            if self.storages:
                return
            
            # 根据配置初始化存储
            if "redis" in settings.AUDIT_LOG_STORAGE_BACKENDS:
                redis_storage = RedisAuditStorage()
                await redis_storage.init()
                self.storages.append(redis_storage)
            
            if "postgres" in settings.AUDIT_LOG_STORAGE_BACKENDS:
                pg_storage = PostgresAuditStorage()
                await pg_storage.init()
                self.storages.append(pg_storage)
            
            if "es" in settings.AUDIT_LOG_STORAGE_BACKENDS:
                es_storage = ESAuditStorage()
                await es_storage.init()
                self.storages.append(es_storage)
            
            audit_logger.info("Audit log service initialized", storages=[s.__class__.__name__ for s in self.storages])

    async def write_audit_log(self, log_data: Dict[str, Any]):
        """写入审计日志（多存储）"""
        # 补充必选字段
        log_data.setdefault("audit_id", str(uuid7()))
        log_data.setdefault("app_name", settings.APP_NAME)
        log_data.setdefault("environment", settings.ENV)
        
        # 验证必选字段
        missing_fields = [f for f in settings.AUDIT_LOG_MANDATORY_FIELDS if f not in log_data]
        if missing_fields:
            audit_logger.error("Missing mandatory audit fields", missing=missing_fields)
            # 开发环境抛出异常，生产环境仅记录
            if settings.ENVIRONMENT != "prod":
                raise ValueError(f"Missing mandatory audit fields: {missing_fields}")
        
        # 异步写入所有存储（无阻塞）
        tasks = []
        for storage in self.storages:
            tasks.append(asyncio.create_task(self._safe_write(storage, log_data)))
        
        # 不等待写入完成（核心性能保障），仅记录异常
        async def monitor_tasks():
            for task in tasks:
                try:
                    await task
                except Exception as e:
                    audit_logger.error("Audit log write failed", storage=task.get_name(), error=str(e))
        
        asyncio.create_task(monitor_tasks())

    async def _safe_write(self, storage: AuditStorage, log_data: Dict[str, Any]):
        """安全写入（捕获异常）"""
        try:
            await storage.write(log_data)
        except Exception as e:
            # 写入失败时，临时写入本地文件兜底
            self._fallback_write(log_data)
            raise e

    def _fallback_write(self, log_data: Dict[str, Any]):
        """本地文件兜底写入（防止日志丢失）"""
        fallback_path = LOG_DIR / "audit_fallback.log"
        with open(fallback_path, "a", encoding="utf-8") as f:
            f.write(f"{orjson.dumps(log_data, default=str)}\n")
        audit_logger.warning("Audit log fallback to file", audit_id=log_data.get("audit_id"))

    async def close(self):
        """关闭所有存储连接"""
        for storage in self.storages:
            try:
                await storage.close()
            except Exception as e:
                audit_logger.error("Failed to close audit storage", error=str(e))
        audit_logger.info("Audit log service closed")

# 全局审计日志服务实例
audit_log_service = AuditLogService()
