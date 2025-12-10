# -*- coding: utf-8 -*-

import time
import asyncio
import aiohttp
import hashlib
from loguru import logger
from fastmcp.client import FastMCPTransport, StreamableHttpTransport, SSETransport
from app.core.config import settings
import redis.asyncio as redis
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status, Request
from jose import JWTError, jwt
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from prometheus_client import Counter, Histogram
from app.core.logger import logger

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_PREFIX}/auth/token")

# 创建指标
FAST_MCP_CALLS = Counter('fastmcp_calls_total', 'Total number of FastMCP calls')
FAST_MCP_LATENCY = Histogram('fastmcp_latency_seconds', 'FastMCP call latency', ['model'])
FAST_MCP_ERRORS = Counter('fastmcp_errors_total', 'Total number of FastMCP errors', ['model'])


# 异步 Redis 客户端
redis_client = redis.from_url(settings.REDIS_URL, decode_responses=True)
limiter = Limiter(key_func=get_remote_address, default_limits=[settings.API_RATE_LIMIT])

# 缓存键前缀
CACHE_PREFIX = "fastmcp:cache:"

def generate_cache_key(model: str, prompt: str) -> str:
    """生成缓存键（模型+提示词哈希）"""
    prompt_hash = hashlib.md5(prompt.encode()).hexdigest()
    return f"{CACHE_PREFIX}{model}:{prompt_hash}"

async def get_cached_response(model: str, prompt: str) -> str | None:
    """获取缓存的模型响应"""
    cache_key = generate_cache_key(model, prompt)
    return await redis_client.get(cache_key)

async def set_cached_response(model: str, prompt: str, response: str) -> None:
    """设置缓存的模型响应（带过期时间）"""
    cache_key = generate_cache_key(model, prompt)
    await redis_client.setex(cache_key, settings.CACHE_TTL_SECONDS, response)
    

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """验证Token，返回当前用户信息"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="无效的认证凭证",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        user_id: str = payload.get("sub")
        tenant_id: str = payload.get("tenant_id")  # 多租户ID
        if user_id is None or tenant_id is None:
            raise credentials_exception
        return {"user_id": user_id, "tenant_id": tenant_id}
    except JWTError:
        raise credentials_exception

# 多租户权限校验（企业级扩展）
async def check_tenant_permission(
    request: Request,
    current_user: dict = Depends(get_current_user)
) -> dict:
    """校验租户是否有权限调用指定模型"""
    tenant_id = current_user["tenant_id"]
    model = request.query_params.get("model") or request.json.get("model")
    # 模拟租户权限配置（生产环境从数据库/Redis读取）
    tenant_models = {
        "tenant_001": ["gpt-3.5-turbo", "qwen-7b"],
        "tenant_002": ["qwen-7b"]
    }
    if model not in tenant_models.get(tenant_id, []):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"租户{tenant_id}无权限调用模型{model}"
        )
    return current_user

# 全局 FastMCP 连接池（单例）
class FastMCPClientPool2:
    def __init__(self):
        self.pool = asyncio.Queue(maxsize=settings.FAST_MCP_POOL_SIZE)
        self.servers = settings.FAST_MCP_SERVERS
        self._initialized = False

    async def init_pool(self):
        """初始化 FastMCP 连接池"""
        if self._initialized:
            return
        for _ in range(settings.FAST_MCP_POOL_SIZE):
            # 轮询选择 FastMCP 服务端（负载均衡）
            server = self.servers[_ % len(self.servers)]
            client = FastMCPTransport(
                url=server,
                timeout=aiohttp.ClientTimeout(total=settings.FAST_MCP_TIMEOUT)
            )
            await self.pool.put(client)
        self._initialized = True
        logger.info(f"FastMCP 连接池初始化完成，大小：{settings.FAST_MCP_POOL_SIZE}")

    async def get_client(self) -> FastMCPTransport:
        """获取连接池中的客户端"""
        if not self._initialized:
            await self.init_pool()
        return await self.pool.get()

    async def release_client(self, client: FastMCPTransport):
        """释放客户端回连接池"""
        await self.pool.put(client)

# 全局 FastMCP 连接池（适配 2.13.3 版本）
class FastMCPClientPool:
    def __init__(self):
        self.pool = asyncio.Queue(maxsize=settings.FAST_MCP_POOL_SIZE)
        self.servers = settings.FAST_MCP_SERVERS
        self._initialized = False
        # 预创建aiohttp ClientSession（统一管理超时和连接池）
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=settings.FAST_MCP_TIMEOUT),
            connector=aiohttp.TCPConnector(limit=settings.FAST_MCP_POOL_SIZE)
        )

    async def init_pool(self):
        """初始化 FastMCP 连接池（适配 2.13.3）"""
        if self._initialized:
            return
        for _ in range(settings.FAST_MCP_POOL_SIZE):
            # 轮询选择 FastMCP 服务端
            server = self.servers[_ % len(self.servers)]
            # 核心修正1：将 server_url 改为 base_url
            # 核心修正2：传递预先创建的 session（包含 timeout）
            client = FastMCPTransport(
                url=server,  # 替换 server_url 为 base_url
                session=self.session  # 传递aiohttp session（包含超时配置）
            )
            await self.pool.put(client)
        self._initialized = True
        logger.info(f"FastMCP 2.13.3 连接池初始化完成，大小：{settings.FAST_MCP_POOL_SIZE}")

    async def get_client(self) -> FastMCPTransport:
        """获取连接池中的客户端"""
        if not self._initialized:
            await self.init_pool()
        return await self.pool.get()

    async def release_client(self, client: FastMCPTransport):
        """释放客户端回连接池"""
        await self.pool.put(client)

    async def close_pool(self):
        """关闭连接池（应用退出时调用）"""
        if self.session:
            await self.session.close()

# 全局单例连接池
mcp_client_pool = FastMCPClientPool()

# FastMCP 调用核心函数（适配 2.13.3）
async def call_fastmcp(
    model: str,
    prompt: str,
    temperature: float = 0.7,
    max_tokens: int = 1024
) -> str:
    """
    调用 FastMCP 2.13.3 服务，返回模型响应
    :param model: 模型名称（如 gpt-3.5-turbo、qwen-7b）
    :param prompt: 输入提示词
    :param temperature: 温度系数
    :param max_tokens: 最大生成token
    :return: 模型响应文本
    """
    start_time = time.time()
    client = None
    for retry in range(settings.FAST_MCP_RETRY_TIMES):
        try:
            # 从连接池获取客户端
            client = await mcp_client_pool.get_client()
            
            # 构建请求（2.13.3 版本兼容 OpenAI 格式）
            response = await client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=max_tokens,
                stream=False  # 非流式响应
            )
            
            # 解析响应（2.13.3 版本结构与 OpenAI 一致）
            result = response.choices[0].message.content
            
            # 释放客户端
            await mcp_client_pool.release_client(client)
            logger.info(f"FastMCP 2.13.3 调用成功，模型：{model}，重试次数：{retry}")

            FAST_MCP_CALLS.inc()
            FAST_MCP_LATENCY.labels(model=model).observe(time.time() - start_time)

            return result        
        except Exception as e:
            FAST_MCP_ERRORS.labels(model=model).inc()
            # 释放客户端（避免连接泄漏）
            if client:
                await mcp_client_pool.release_client(client)
            logger.error(f"FastMCP 调用失败（重试{retry+1}/{settings.FAST_MCP_RETRY_TIMES}）：{str(e)}")            

            # 降级策略：尝试从缓存获取
            if retry == settings.FAST_MCP_RETRY_TIMES - 1:
                cached_response = await get_cached_response(model, prompt)
                if cached_response:
                    logger.warning(f"FastMCP 调用失败，使用缓存响应，模型：{model}")
                    return cached_response
                logger.warning(f"FastMCP 调用降级，模型：{model}")
                return "暂时无法获取响应，请稍后重试"
            
            await asyncio.sleep(0.5)  # 重试间隔