# app/main.py
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.logger import logger
from app.middleware.logging import RequestContextLoggingMiddleware
from app.middleware.tracing import TracingMiddleware
from app.exceptions.handlers import http_exception_handler, generic_exception_handler
from app.routers import api

import sentry_sdk
from sentry_sdk.integrations.fastapi import FastApiIntegration
from sentry_sdk.integrations.structlog import StructlogIntegration

# 在应用创建和中间件加载前初始化Sentry
sentry_sdk.init(
    dsn=settings.SENTRY_DSN,  # 关键！从Sentry项目获取的密钥
    #dsn="https://your-dsn-here@sentry.io/123456", #初始化Sentry（生产环境必须配置DSN
    integrations=[
        FastApiIntegration(),  # 自动捕获FastAPI路由异常
        StructlogIntegration(),  # 与structlog集成，将日志上下文带给Sentry事件
    ],
    # 企业级配置建议
    traces_sample_rate=0.1,  # 性能监控采样率，1.0为100%。生产环境可调低以节省配额
    environment=settings.ENVIRONMENT,  # 区分 "production", "staging", "development"
    release="your-app-name@1.0.0",  # 关联代码版本，便于归因
    send_default_pii=False,  # 是否发送用户个人身份信息，需根据隐私政策决定
)

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
