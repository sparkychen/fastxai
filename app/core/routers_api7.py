# app/routers/api.py
from fastapi import APIRouter, Depends, Request
from app.core.logger import logger, bind_context
from app.core.config import settings

router = APIRouter(prefix=settings.API_PREFIX)

# 模拟认证依赖（绑定用户ID到日志）
async def get_current_user(request: Request):
    """模拟获取当前用户（实际对接FastAPI-Users）"""
    user = {"id": "123456", "tenant_id": "tenant-001", "username": "admin"}
    # 绑定用户上下文到日志
    bind_context(user_id=user["id"], tenant_id=user["tenant_id"])
    request.state.user = user
    return user

@router.get("/health")
async def health_check():
    """健康检查接口（基础日志）"""
    logger.info("Health check requested")
    return {"status": "healthy"}

@router.post("/users")
async def create_user(
    request: Request,
    user_data: dict,
    current_user: dict = Depends(get_current_user)
):
    """创建用户接口（企业级日志示例）"""
    # 业务日志（携带上下文）
    logger.info(
        "Creating user",
        user_data=user_data,  # 敏感字段会自动脱敏
        operator_id=current_user["id"],
    )
    # 模拟业务逻辑
    new_user = {"id": "789012", "username": user_data["username"]}
    # 成功日志
    logger.info(
        "User created successfully",
        new_user_id=new_user["id"],
        tenant_id=current_user["tenant_id"],
    )
    return new_user

@router.get("/users/{user_id}")
async def get_user(
    user_id: str,
    current_user: dict = Depends(get_current_user)
):
    """查询用户接口（带错误日志）"""
    try:
        # 模拟业务异常
        if user_id == "invalid":
            raise ValueError("Invalid user ID")
        logger.info("User queried", user_id=user_id)
        return {"id": user_id, "username": "test_user"}
    except ValueError as e:
        logger.error(
            "User query failed",
            user_id=user_id,
            error=str(e),
            exc_info=True,
        )
        raise HTTPException(status_code=400, detail=str(e))
