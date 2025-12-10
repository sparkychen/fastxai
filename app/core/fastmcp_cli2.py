# -*- coding: utf-8 -*-

"""
Docstring for app.core.fastmcp_cli2

1. 彻底移除 FastMCP 客户端类：删除所有 FastMCPTransport 相关导入和使用，改用 aiohttp 直接调用 HTTP 接口（FastMCP 本质是兼容 OpenAI 的 HTTP 服务）；
2. 连接池重构：FastMCPClientPool 改为管理 aiohttp.ClientSession，保留原变量名（mcp_client_pool），兼容原有代码的导入和调用；
3. 接口标准化：FastMCP 2.13.3 兼容 OpenAI 的 /v1/chat/completions 接口，直接 POST 该路径即可；
4. 保留所有原有特性：缓存、多租户权限、限流、重试、降级等逻辑完全保留，无需修改其他文件；
5. 轮询负载均衡：保留服务端轮询逻辑，确保多服务端时的负载均衡。
"""

import time
import asyncio
import aiohttp
import hashlib
from app.core.config import settings
import redis.asyncio as redis
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer
from fastapi import Depends, HTTPException, status, Request
from jose import JWTError, jwt
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from prometheus_client import Counter, Histogram, CollectorRegistry
from app.core.logger import logger


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_PREFIX}/auth/token")

# 创建自定义注册表（避免使用默认的REGISTRY）
custom_registry = CollectorRegistry()
# 创建指标
FAST_MCP_CALLS = Counter('fastmcp_calls_total', 'Total number of FastMCP calls', registry=custom_registry)
FAST_MCP_LATENCY = Histogram('fastmcp_latency_seconds', 'FastMCP call latency', ['model'], registry=custom_registry)
FAST_MCP_ERRORS = Counter('fastmcp_errors_total', 'Total number of FastMCP errors', ['model'], registry=custom_registry)

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
    # 兼容 GET/POST 请求的参数获取
    model = request.query_params.get("model")
    if not model and request.method == "POST":
        try:
            body = await request.json()
            model = body.get("model")
        except:
            model = None
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

# 全局 aiohttp 连接池（替代 FastMCP 客户端池，彻底绕开官方类）
class FastMCPClientPool:
    def __init__(self):
        self.session: aiohttp.ClientSession = None
        self.servers = settings.FAST_MCP_SERVERS
        self._initialized = False
        self._server_index = 0  # 轮询索引

    async def init_pool(self):
        """初始化 aiohttp 连接池（纯 HTTP 调用）"""
        if self._initialized:
            return
        # 配置 aiohttp 连接池（企业级参数）
        timeout = aiohttp.ClientTimeout(total=settings.FAST_MCP_TIMEOUT)
        connector = aiohttp.TCPConnector(
            limit=settings.FAST_MCP_POOL_SIZE,  # 最大并发连接数
            limit_per_host=5,  # 单主机最大连接数
            ttl_dns_cache=300,  # DNS 缓存时间
            ssl=False  # 测试环境关闭 SSL，生产环境改为 True
        )
        self.session = aiohttp.ClientSession(
            timeout=timeout,
            connector=connector,
            headers={"Content-Type": "application/json"}  # 默认请求头
        )
        self._initialized = True
        logger.info(f"FastMCP HTTP 连接池初始化完成，服务端列表：{self.servers}")

    def _get_next_server(self) -> str:
        """轮询获取下一个 FastMCP 服务端地址"""
        server = self.servers[self._server_index]
        self._server_index = (self._server_index + 1) % len(self.servers)
        return server

    async def get_session(self) -> aiohttp.ClientSession:
        """获取 aiohttp 会话"""
        if not self._initialized:
            await self.init_pool()
        return self.session

    async def close_pool(self):
        """关闭连接池（应用退出时调用）"""
        if self._initialized and self.session:
            await self.session.close()
            self._initialized = False
            logger.info("FastMCP HTTP 连接池已关闭")

# 全局单例连接池（变量名保持不变，兼容原有代码）
mcp_client_pool = FastMCPClientPool()

# FastMCP 核心调用函数（纯 HTTP 调用，兼容原有参数）
async def call_fastmcp(
    model: str,
    prompt: str,
    temperature: float = 0.7,
    max_tokens: int = 1024
) -> str:
    """
    纯 HTTP 调用 FastMCP 2.13.3 服务（绕开官方客户端类）
    :param model: 模型名称
    :param prompt: 输入提示词
    :param temperature: 温度系数
    :param max_tokens: 最大生成token
    :return: 模型响应文本
    """
    FAST_MCP_CALLS.inc()
    start_time = time.time()
    client = None
    # 优先读取缓存
    cached_response = await get_cached_response(model, prompt)
    if cached_response:
        logger.info(f"FastMCP 缓存命中，模型：{model}")
        return cached_response

    session = await mcp_client_pool.get_session()
    # 构建 OpenAI 兼容的请求体（FastMCP 2.13.3 标准接口）
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "stream": False
    }

    for retry in range(settings.FAST_MCP_RETRY_TIMES):
        try:
            # 轮询选择服务端
            server = mcp_client_pool._get_next_server()
            url = f"{server}/v1/chat/completions"  # FastMCP 标准接口路径

            # 异步 POST 请求（核心：纯 HTTP 调用）
            async with session.post(
                url=url,
                json=payload,
                timeout=aiohttp.ClientTimeout(total=settings.FAST_MCP_TIMEOUT)
            ) as response:
                # 校验响应状态
                if response.status != 200:
                    err_detail = await response.text()
                    raise Exception(f"服务端响应异常：{response.status} - {err_detail}")
                
                # 解析响应（FastMCP 2.13.3 兼容 OpenAI 格式）
                result = await response.json()
                content = result["choices"][0]["message"]["content"]
                
                # 写入缓存
                await set_cached_response(model, prompt, content)
                
                logger.info(f"FastMCP HTTP 调用成功，模型：{model}，服务端：{server}，重试次数：{retry}")
                
                FAST_MCP_LATENCY.labels(model=model).observe(time.time() - start_time)

                return content
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