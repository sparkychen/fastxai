# -*- coding: utf-8 -*-

import time
import asyncio
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, Request, APIRouter, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response
from app.core.logger import logger
from app.core.config import settings
from app.core.fastmcp_cli import call_fastmcp
from app.core.fastmcp_cli import limiter, get_cached_response, set_cached_response, get_current_user, check_tenant_permission
from app.core.fastapi_user import fastapi_users, current_user, current_superuser

router = APIRouter(prefix="/mcp/v1", tags=["fastmcp server"])

# 请求数计数器
REQUEST_COUNT = Counter(
    "fastapi_fastmcp_requests_total",
    "Total number of requests to FastAPI + FastMCP service",
    ["endpoint", "model", "status"]
)
# 响应时间直方图
REQUEST_DURATION = Histogram(
    "fastapi_fastmcp_request_duration_seconds",
    "Duration of requests to FastAPI + FastMCP service",
    ["endpoint", "model"]
)

# ========== 监控接口 ==========
@router.get("/metrics")
async def metrics():
    """Prometheus 监控指标接口"""
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)

# ========== 认证接口 ==========
@router.post(f"{settings.API_PREFIX}/auth/token")
@limiter.limit(settings.API_RATE_LIMIT)
async def login_for_access_token(request: Request, username: str, password: str):
    """获取 JWT Token（生产环境需对接企业用户系统）"""
    # 模拟用户验证（生产环境从数据库查询）
    if username != "admin" or password != "password123":  # 生产环境用哈希验证
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误"
        )
    # 生成 Token（包含租户ID）
    access_token = jwt.encode(
        {
            "sub": username,
            "tenant_id": "tenant_001",
            "exp": time.time() + settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60
        },
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )
    return {"access_token": access_token, "token_type": "bearer"}

# ========== 核心 AI 接口（单条请求） ==========
@router.post(f"{settings.API_PREFIX}/ai/chat")
@limiter.limit(settings.API_RATE_LIMIT)
async def chat(
    request: Request,
    model: str,
    prompt: str,
    temperature: float = 0.7,
    max_tokens: int = 1024,
    current_user: dict = Depends(check_tenant_permission)  # 权限+租户校验
):
    """
    企业级 AI 对话接口（带缓存、监控、审计）
    :param model: 模型名称
    :param prompt: 输入提示词
    :param temperature: 温度系数
    :param max_tokens: 最大生成token
    :return: 模型响应
    """
    start_time = time.time()
    status = "success"
    
    try:
        # 1. 检查缓存（热点请求直接返回）
        cached_response = await get_cached_response(model, prompt)
        if cached_response:
            REQUEST_COUNT.labels(endpoint="/ai/chat", model=model, status="hit_cache").inc()
            logger.info(f"缓存命中，模型：{model}，用户：{current_user['user_id']}")
            return {
                "code": 200,
                "data": {"response": cached_response},
                "msg": "success",
                "cache_hit": True
            }
        
        # 2. 调用 FastMCP 获取模型响应
        response = await call_fastmcp(model, prompt, temperature, max_tokens)
        
        # 3. 设置缓存（非降级响应才缓存）
        if response != "暂时无法获取响应，请稍后重试":
            await set_cached_response(model, prompt, response)
        
        # 4. 记录审计日志（企业级合规）
        logger.info(
            "AI chat request",
            user_id=current_user["user_id"],
            tenant_id=current_user["tenant_id"],
            model=model,
            prompt=prompt[:50],  # 截断长提示词
            status="success"
        )
        
        return {
            "code": 200,
            "data": {"response": response},
            "msg": "success",
            "cache_hit": False
        }
    
    except Exception as e:
        status = "error"
        logger.error(
            "AI chat failed",
            user_id=current_user["user_id"],
            model=model,
            error=str(e)
        )
        raise HTTPException(status_code=500, detail=f"服务异常：{str(e)}")
    
    finally:
        # 5. 记录监控指标
        duration = time.time() - start_time
        REQUEST_COUNT.labels(endpoint="/ai/chat", model=model, status=status).inc()
        REQUEST_DURATION.labels(endpoint="/ai/chat", model=model).observe(duration)

# ========== 批量 AI 接口（高性能） ==========
@router.post(f"{settings.API_PREFIX}/ai/batch_chat")
@limiter.limit(settings.API_RATE_LIMIT)  # 批量接口限流更严格
async def batch_chat(
    request: Request,
    model: str,
    prompts: list[str],
    current_user: dict = Depends(check_tenant_permission)
):
    """
    批量 AI 对话接口（异步并发调用 FastMCP）RateLimitExceeded
    :param model: 模型名称
    :param prompts: 批量提示词列表
    :return: 批量响应
    """
    start_time = time.time()
    
    # 异步并发处理批量请求（高性能核心）
    tasks = []
    for prompt in prompts:
        # 先查缓存，再调用 FastMCP
        cached = await get_cached_response(model, prompt)
        if cached:
            tasks.append(asyncio.create_task(asyncio.sleep(0, result=cached)))
        else:
            tasks.append(call_fastmcp(model, prompt))
    
    # 等待所有任务完成
    responses = await asyncio.gather(*tasks, return_exceptions=True)
    
    # 整理结果（处理异常）
    result = []
    for i, resp in enumerate(responses):
        if isinstance(resp, Exception):
            result.append({"prompt": prompts[i], "response": "处理失败", "error": str(resp)})
        else:
            result.append({"prompt": prompts[i], "response": resp})
            # 缓存成功的响应
            if resp != "暂时无法获取响应，请稍后重试":
                await set_cached_response(model, prompts[i], resp)
    
    # 监控 + 审计
    duration = time.time() - start_time
    REQUEST_COUNT.labels(endpoint="/ai/batch_chat", model=model, status="success").inc()
    REQUEST_DURATION.labels(endpoint="/ai/batch_chat", model=model).observe(duration)
    logger.info(f"批量处理完成，用户：{current_user['user_id']}，数量：{len(prompts)}，耗时：{duration:.2f}s")
    
    return {
        "code": 200,
        "data": result,
        "msg": "success",
        "total": len(result),
        "duration": duration
    }