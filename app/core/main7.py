# app/main.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.logger import logger
from app.middleware.logging import RequestContextLoggingMiddleware
from app.middleware.tracing import TracingMiddleware
from app.exceptions.handlers import http_exception_handler, generic_exception_handler
from app.routers import api

# ========== 1. 创建FastAPI应用 ==========
app = FastAPI(
    title=settings.APP_NAME,
    docs_url=None if settings.ENV == "prod" else "/docs",
    redoc_url=None if settings.ENV == "prod" else "/redoc",
)

# ========== 2. 注册中间件（顺序重要） ==========
# 1. CORS中间件
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# 2. 分布式追踪中间件（先于日志中间件）
if settings.TRACING_ENABLE:
    app.add_middleware(TracingMiddleware)
# 3. 请求上下文日志中间件（核心）
app.add_middleware(RequestContextLoggingMiddleware)

# ========== 3. 注册异常处理器 ==========
app.add_exception_handler(HTTPException, http_exception_handler)
app.add_exception_handler(Exception, generic_exception_handler)

# ========== 4. 注册路由 ==========
app.include_router(api.router)

# ========== 5. 生命周期钩子 ==========
@app.on_event("startup")
async def startup_event():
    """应用启动日志"""
    logger.info(
        "Application started",
        env=settings.ENV,
        log_level=settings.LOG.LEVEL,
        log_format=settings.LOG.FORMAT,
        async_log=settings.LOG.ENABLE_ASYNC,
    )

@app.on_event("shutdown")
async def shutdown_event():
    """应用关闭日志（确保异步日志刷完）"""
    logger.info("Application shutting down")
    # 等待异步日志处理器刷新
    if settings.LOG.ENABLE_ASYNC:
        from app.utils.async_logger import async_log_processor
        await async_log_processor.flush() 
        import time
        time.sleep(settings.LOG.ASYNC_FLUSH_INTERVAL + 1)
