# app/main.py - 企业级：FastAPI集成
from fastapi import FastAPI
from app.logging import init_logging
from fastapi_structlog import StructLogMiddleware
from structlog import get_logger
from fastapi_structlog import init_logging, StructlogMiddleware, AccessLogMiddleware, CurrentScopeSetMiddleware
from asgi_correlation_id import CorrelationIdMiddleware  # 需额外安装：pip install asgi-correlation-id

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

# 企业级：初始化日志
logger = init_logging()

app = FastAPI(
    title="FastAPI Structlog Project",
    version="1.0.0",
    docs_url=None,  # 生产环境禁用Swagger
    redoc_url=None,  # 生产环境禁用ReDoc
)

app.add_middleware(CurrentScopeSetMiddleware)  # 1. 设置上下文
app.add_middleware(
    CorrelationIdMiddleware,
    header_name="X-Request-ID",  # 可配置为任意头名称
    # 可选：自定义ID生成器
    # generator=lambda: uuid.uuid4().hex,
)    # 2. 生成请求ID
app.add_middleware(StructlogMiddleware)        # 3. 将请求ID注入日志上下文
app.add_middleware(AccessLogMiddleware)        # 4. 记录访问日志（格式可自定义[citation:1]）


def set_log_level(level: str):
    """动态设置日志级别（生产环境可API调整）"""
    level = level.upper()
    if level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]:
        get_logger().setLevel(level)
        return True

    return False


# 企业级：在API中提供日志级别调整端点

@app.get("/admin/log-level")
async def set_log_level_api(level: str = "INFO"):
    if set_log_level(level):
        return {"status": "success", "level": level}
    return {"status": "error", "message": "Invalid log level"}

# 企业级：集成StructLogMiddleware（关键！）
app.add_middleware(
    StructLogMiddleware,
    logger=logger,
    # 企业级：配置请求ID生成
    request_id_generator=lambda: f"req-{uuid.uuid4().hex[:8]}",
    # 企业级：过滤敏感字段
    sensitive_fields=["password", "token", "api_key"],
    # 企业级：日志级别动态调整
    log_level_mapping={
        "info": "INFO",
        "debug": "DEBUG",
        "warning": "WARNING",
        "error": "ERROR",
        "critical": "CRITICAL",
    },
)

@app.get("/users/me")
async def read_users_me(user: User = Depends(current_user)):
    # 企业级：使用structlog记录
    logger.info(
        "User profile requested",
        event="user_profile_request",
        user_id=user.id,
        username=user.username,
        ip_address=request.client.host,
        # 企业级：避免记录敏感信息
        # password=user.password,  # 不要记录
    )
    return user