# -*- coding: utf-8 -*-

from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from contextlib import asynccontextmanager
import structlog
import uvloop
import asyncio
from app.db.engine import init_async_engines, close_async_engines, check_db_health, get_async_session
from app.db.config import db_settings
from app.db.models.base import BaseModel
from app.db.crud.base import BaseCRUD
from pydantic import BaseModel as PydanticModel
from uuid import UUID
from datetime import datetime

# 替换默认事件循环为uvloop（性能提升30%+）
asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())

# 结构化日志配置
structlog.configure(
    processors=[
        structlog.contextvars.merge_contextvars,
        structlog.processors.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ]
)
logger = structlog.get_logger("app")

# ========== 应用生命周期 ==========
@asynccontextmanager
async def app_lifespan(app: FastAPI):
    # 启动：初始化数据库引擎
    logger.info("Starting enterprise FastAPI app")
    init_async_engines()
    # 健康检查
    db_health = await check_db_health()
    if db_health["status"] != "healthy":
        logger.error("DB health check failed", health=db_health)
        raise RuntimeError("Database initialization failed")
    logger.info("App initialized successfully", db_health=db_health)
    yield
    # 关闭：清理引擎
    logger.info("Shutting down app")
    await close_async_engines()
    logger.info("App shutdown completed")

# ========== 创建应用 ==========
app = FastAPI(
    title="Enterprise FastAPI + PostgreSQL",
    version="1.0.0",
    lifespan=app_lifespan,
    docs_url="/docs" if db_settings.ENVIRONMENT != "production" else None,
    redoc_url="/redoc" if db_settings.ENVIRONMENT != "production" else None,
)

# ========== 安全中间件 ==========
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://your-domain.com"],  # 生产环境严格限制
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["Authorization", "Content-Type"],
)

# ========== 健康检查接口 ==========
@app.get("/health", tags=["system"])
async def health_check(
    db_health: dict = Depends(check_db_health)
):
    return {
        "status": "healthy" if db_health["status"] == "healthy" else "unhealthy",
        "database": db_health,
        "version": "1.0.0",
        "timestamp": datetime.utcnow()
    }

# ========== 示例业务接口 ==========
# 1. 示例模型（实际项目拆分到app/db/models/user.py）
from sqlalchemy import Column, String
class User(BaseModel):
    __tablename__ = "users"
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(100), unique=True, nullable=False, index=True)
    full_name = Column(String(100), nullable=True)

# 2. 示例Pydantic模型
class UserCreate(PydanticModel):
    username: str
    email: str
    full_name: Optional[str] = None

class UserResponse(PydanticModel):
    id: UUID
    username: str
    email: str
    full_name: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

# 3. CRUD实例
user_crud = BaseCRUD(User)

# 4. 业务接口
@app.post("/users", response_model=UserResponse, tags=["users"])
async def create_user(
    user_in: UserCreate,
    db: AsyncSession = Depends(get_async_session)  # 写库
):
    # 检查用户名/邮箱唯一性（示例）
    if await user_crud.count(db, filters={"username": user_in.username}, read_only=True):
        raise HTTPException(400, detail="Username already exists")
    return await user_crud.create(db, obj_in=user_in.model_dump())

@app.get("/users/{user_id}", response_model=UserResponse, tags=["users"])
async def get_user(
    user_id: UUID,
    db: AsyncSession = Depends(get_async_session)  # 读库
):
    user = await user_crud.get(db, id=user_id, read_only=True)
    if not user:
        raise HTTPException(404, detail="User not found")
    return user

@app.get("/users", response_model=list[UserResponse], tags=["users"])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_async_session)  # 读库
):
    return await user_crud.get_multi(db, skip=skip, limit=limit, read_only=True)
