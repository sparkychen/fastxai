# -*- coding: utf-8 -*-

from typing import List, Set, Callable, Optional
from functools import wraps
from fastapi import HTTPException, status, Depends
from enum import Enum
from app.services.auth_service import auth_service
from app.models.user import User
from app.core.logger import setup_strcutlogger

logger = setup_strcutlogger()

class Permission(str, Enum):
    """系统权限枚举"""
    # 用户权限
    USER_READ = "user:read"
    USER_WRITE = "user:write"
    USER_DELETE = "user:delete"
    
    # 角色权限
    ROLE_READ = "role:read"
    ROLE_WRITE = "role:write"
    
    # 系统权限
    SYSTEM_ADMIN = "system:admin"
    SYSTEM_AUDIT = "system:audit"
    
    # API权限
    API_READ = "api:read"
    API_WRITE = "api:write"
    API_DELETE = "api:delete"
    
    # 数据权限
    DATA_READ = "data:read"
    DATA_WRITE = "data:write"
    DATA_EXPORT = "data:export"
    
    # 工作流权限
    WORKFLOW_EXECUTE = "workflow:execute"
    WORKFLOW_MANAGE = "workflow:manage"

class Role(str, Enum):
    """系统角色枚举"""
    SUPER_ADMIN = "super_admin"
    ADMIN = "admin"
    MANAGER = "manager"
    USER = "user"
    GUEST = "guest"
    AUDITOR = "auditor"

# 角色-权限映射
ROLE_PERMISSIONS = {
    Role.SUPER_ADMIN: {
        Permission.SYSTEM_ADMIN,
        Permission.USER_READ, Permission.USER_WRITE, Permission.USER_DELETE,
        Permission.ROLE_READ, Permission.ROLE_WRITE,
        Permission.API_READ, Permission.API_WRITE, Permission.API_DELETE,
        Permission.DATA_READ, Permission.DATA_WRITE, Permission.DATA_EXPORT,
        Permission.WORKFLOW_EXECUTE, Permission.WORKFLOW_MANAGE,
    },
    Role.ADMIN: {
        Permission.USER_READ, Permission.USER_WRITE,
        Permission.API_READ, Permission.API_WRITE,
        Permission.DATA_READ, Permission.DATA_WRITE,
        Permission.WORKFLOW_EXECUTE, Permission.WORKFLOW_MANAGE,
    },
    Role.MANAGER: {
        Permission.USER_READ,
        Permission.API_READ,
        Permission.DATA_READ, Permission.DATA_EXPORT,
        Permission.WORKFLOW_EXECUTE,
    },
    Role.USER: {
        Permission.USER_READ,
        Permission.API_READ,
        Permission.DATA_READ,
    },
    Role.GUEST: {
        Permission.API_READ,
    },
    Role.AUDITOR: {
        Permission.SYSTEM_AUDIT,
        Permission.USER_READ,
        Permission.API_READ,
        Permission.DATA_READ,
    },
}

class RBACService:
    """基于角色的访问控制服务"""
    
    def __init__(self):
        self.user_roles_cache = {}  # 简单缓存，生产环境用Redis
    
    def has_permission(self, user: User, required_permission: Permission) -> bool:
        """检查用户是否拥有指定权限"""
        user_permissions = self.get_user_permissions(user)
        return required_permission in user_permissions
    
    def has_any_permission(self, user: User, required_permissions: List[Permission]) -> bool:
        """检查用户是否拥有任意指定权限"""
        user_permissions = self.get_user_permissions(user)
        return any(perm in user_permissions for perm in required_permissions)
    
    def has_all_permissions(self, user: User, required_permissions: List[Permission]) -> bool:
        """检查用户是否拥有所有指定权限"""
        user_permissions = self.get_user_permissions(user)
        return all(perm in user_permissions for perm in required_permissions)
    
    def get_user_permissions(self, user: User) -> Set[Permission]:
        """获取用户所有权限"""
        if user.id in self.user_roles_cache:
            return self.user_roles_cache[user.id]
        
        permissions = set()
        
        # 从数据库获取用户角色
        user_roles = user.roles or []
        
        for role_name in user_roles:
            try:
                role = Role(role_name)
                permissions.update(ROLE_PERMISSIONS.get(role, set()))
            except ValueError:
                logger.warning(f"Unknown role: {role_name}", user_id=user.id)
        
        # 添加用户特定权限
        if user.permissions:
            for perm_name in user.permissions:
                try:
                    perm = Permission(perm_name)
                    permissions.add(perm)
                except ValueError:
                    logger.warning(f"Unknown permission: {perm_name}", user_id=user.id)
        
        # 缓存结果
        self.user_roles_cache[user.id] = permissions
        
        return permissions
    
    def require_permission(self, permission: Permission):
        """权限检查装饰器"""
        def decorator(func: Callable):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # 获取当前用户
                current_user = kwargs.get('current_user')
                if not current_user:
                    # 从参数中查找
                    for arg in kwargs.values():
                        if isinstance(arg, User):
                            current_user = arg
                            break
                
                if not current_user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication required",
                    )
                
                # 检查权限
                if not self.has_permission(current_user, permission):
                    logger.warning(
                        "Permission denied",
                        user_id=current_user.id,
                        permission=permission,
                        endpoint=func.__name__
                    )
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Required permission: {permission}",
                    )
                
                return await func(*args, **kwargs)
            return wrapper
        return decorator
    
    def require_any_permission(self, permissions: List[Permission]):
        """检查任意权限装饰器"""
        def decorator(func: Callable):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                current_user = kwargs.get('current_user')
                if not current_user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication required",
                    )
                
                if not self.has_any_permission(current_user, permissions):
                    logger.warning(
                        "Any permission denied",
                        user_id=current_user.id,
                        required_permissions=permissions,
                        endpoint=func.__name__
                    )
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Required any permission: {permissions}",
                    )
                
                return await func(*args, **kwargs)
            return wrapper
        return decorator
    
    def require_role(self, required_role: Role):
        """角色检查装饰器"""
        def decorator(func: Callable):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                current_user = kwargs.get('current_user')
                if not current_user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication required",
                    )
                
                user_roles = current_user.roles or []
                if required_role.value not in user_roles:
                    logger.warning(
                        "Role denied",
                        user_id=current_user.id,
                        required_role=required_role,
                        user_roles=user_roles,
                        endpoint=func.__name__
                    )
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Required role: {required_role}",
                    )
                
                return await func(*args, **kwargs)
            return wrapper
        return decorator

# 创建全局RBAC服务实例
rbac_service = RBACService()

# 快捷依赖项
def require_permission(permission: Permission):
    """FastAPI依赖项：检查权限"""
    async def permission_dependency(current_user: User = Depends(auth_service.get_current_user)):
        if not rbac_service.has_permission(current_user, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required permission: {permission}",
            )
        return current_user
    return permission_dependency

def require_any_permission(permissions: List[Permission]):
    """FastAPI依赖项：检查任意权限"""
    async def permission_dependency(current_user: User = Depends(auth_service.get_current_user)):
        if not rbac_service.has_any_permission(current_user, permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required any permission: {permissions}",
            )
        return current_user
    return permission_dependency

def require_role(role: Role):
    """FastAPI依赖项：检查角色"""
    async def role_dependency(current_user: User = Depends(auth_service.get_current_user)):
        user_roles = current_user.roles or []
        if role.value not in user_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Required role: {role}",
            )
        return current_user
    return role_dependency