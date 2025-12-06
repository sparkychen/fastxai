# -*- coding: utf-8 -*-

from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from uuid import uuid4
import hashlib
import hmac
import base64
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import Column, String, DateTime, Boolean, JSON
import structlog

from ..config.database import Base
from .sc_config import security_settings
from .auth import auth_service

logger = structlog.get_logger()

class APIKey(Base):
    """API密钥数据库模型"""
    __tablename__ = "api_keys"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid4()))
    key_id = Column(String(50), unique=True, index=True, nullable=False)
    key_hash = Column(String(128), nullable=False)  # 存储哈希值，不存储原始密钥
    user_id = Column(String(36), index=True, nullable=False)
    name = Column(String(100), nullable=False)
    description = Column(String(500))
    
    # 权限和范围
    scopes = Column(JSON, default=list)  # 权限范围列表
    rate_limit = Column(String(50), default="100/minute")
    
    # 状态
    is_active = Column(Boolean, default=True)
    last_used = Column(DateTime, nullable=True)
    use_count = Column(Integer, default=0)
    
    # 有效期
    expires_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    revoked_at = Column(DateTime, nullable=True)
    
    # 元数据
    metadata = Column(JSON, default=dict)
    ip_whitelist = Column(JSON, default=list)
    user_agent_pattern = Column(String(500), nullable=True)

class APIKeyService:
    """API密钥管理服务"""
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
    
    @staticmethod
    def generate_key() -> Dict[str, str]:
        """生成新的API密钥"""
        # 生成密钥ID和密钥
        key_id = f"key_{uuid4().hex[:16]}"
        secret_key = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')
        
        # 生成完整的API密钥（显示给用户）
        api_key = f"{key_id}.{secret_key}"
        
        return {
            "key_id": key_id,
            "secret_key": secret_key,
            "api_key": api_key,  # 完整密钥，只显示一次
        }
    
    @staticmethod
    def hash_key(secret_key: str) -> str:
        """哈希API密钥（用于存储）"""
        # 使用HMAC-SHA256进行哈希
        salt = security_settings.JWT_SECRET_KEY.encode()
        h = hmac.new(salt, secret_key.encode(), hashlib.sha256)
        return h.hexdigest()
    
    @staticmethod
    def validate_key_format(api_key: str) -> bool:
        """验证API密钥格式"""
        parts = api_key.split('.')
        return len(parts) == 2 and len(parts[0]) == 16 and len(parts[1]) == 43
    
    @staticmethod
    def parse_key(api_key: str) -> Optional[Dict[str, str]]:
        """解析API密钥"""
        if not api_key or '.' not in api_key:
            return None
        
        parts = api_key.split('.', 1)
        return {
            "key_id": parts[0],
            "secret_key": parts[1],
        }
    
    async def create_key(
        self,
        user_id: str,
        name: str,
        description: Optional[str] = None,
        scopes: Optional[List[str]] = None,
        expires_in_days: Optional[int] = None,
        ip_whitelist: Optional[List[str]] = None,
        **metadata
    ) -> Dict[str, Any]:
        """创建新的API密钥"""
        # 生成密钥
        key_data = self.generate_key()
        
        # 计算过期时间
        expires_at = None
        if expires_in_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
        
        # 创建API密钥记录
        api_key_record = APIKey(
            key_id=key_data["key_id"],
            key_hash=self.hash_key(key_data["secret_key"]),
            user_id=user_id,
            name=name,
            description=description,
            scopes=scopes or ["api:read"],
            expires_at=expires_at,
            ip_whitelist=ip_whitelist or [],
            metadata=metadata,
        )
        
        self.db_session.add(api_key_record)
        await self.db_session.commit()
        
        # 返回密钥数据（只显示一次）
        return {
            "id": api_key_record.id,
            "name": name,
            "api_key": key_data["api_key"],  # 完整密钥，只显示一次
            "key_id": key_data["key_id"],
            "scopes": scopes,
            "expires_at": expires_at,
            "created_at": api_key_record.created_at,
            "warning": "Store this API key securely. It will not be shown again.",
        }
    
    async def validate_key(
        self,
        api_key: str,
        required_scopes: Optional[List[str]] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Optional[APIKey]:
        """验证API密钥"""
        # 解析密钥
        key_parts = self.parse_key(api_key)
        if not key_parts:
            return None
        
        # 查询数据库
        from sqlalchemy import select
        stmt = select(APIKey).where(
            APIKey.key_id == key_parts["key_id"],
            APIKey.is_active == True
        )
        result = await self.db_session.execute(stmt)
        api_key_record = result.scalar_one_or_none()
        
        if not api_key_record:
            logger.warning("API key not found", key_id=key_parts["key_id"])
            return None
        
        # 检查是否已撤销
        if api_key_record.revoked_at:
            logger.warning("API key revoked", key_id=key_parts["key_id"])
            return None
        
        # 检查是否过期
        if api_key_record.expires_at and api_key_record.expires_at < datetime.utcnow():
            logger.warning("API key expired", key_id=key_parts["key_id"])
            return None
        
        # 验证密钥哈希
        provided_hash = self.hash_key(key_parts["secret_key"])
        if not hmac.compare_digest(provided_hash, api_key_record.key_hash):
            logger.warning("API key validation failed", key_id=key_parts["key_id"])
            return None
        
        # 检查IP白名单
        if api_key_record.ip_whitelist and client_ip:
            if client_ip not in api_key_record.ip_whitelist:
                logger.warning("IP not in whitelist", 
                              key_id=key_parts["key_id"], 
                              client_ip=client_ip)
                return None
        
        # 检查User-Agent模式
        if api_key_record.user_agent_pattern and user_agent:
            if not re.search(api_key_record.user_agent_pattern, user_agent):
                logger.warning("User-Agent pattern mismatch", 
                              key_id=key_parts["key_id"], 
                              user_agent=user_agent[:50])
                return None
        
        # 检查权限范围
        if required_scopes:
            key_scopes = set(api_key_record.scopes or [])
            required_scopes_set = set(required_scopes)
            
            if not required_scopes_set.issubset(key_scopes):
                logger.warning("Insufficient scopes", 
                              key_id=key_parts["key_id"],
                              required=required_scopes,
                              available=list(key_scopes))
                return None
        
        # 更新使用统计
        api_key_record.last_used = datetime.utcnow()
        api_key_record.use_count += 1
        await self.db_session.commit()
        
        logger.info("API key validated successfully", key_id=key_parts["key_id"])
        return api_key_record
    
    async def revoke_key(self, key_id: str, user_id: str) -> bool:
        """撤销API密钥"""
        from sqlalchemy import select, update
        
        stmt = select(APIKey).where(
            APIKey.key_id == key_id,
            APIKey.user_id == user_id,
            APIKey.is_active == True
        )
        result = await self.db_session.execute(stmt)
        api_key_record = result.scalar_one_or_none()
        
        if not api_key_record:
            return False
        
        # 标记为撤销
        api_key_record.is_active = False
        api_key_record.revoked_at = datetime.utcnow()
        
        await self.db_session.commit()
        
        logger.info("API key revoked", key_id=key_id, user_id=user_id)
        return True
    
    async def list_user_keys(self, user_id: str) -> List[Dict[str, Any]]:
        """列出用户的所有API密钥"""
        from sqlalchemy import select
        
        stmt = select(APIKey).where(
            APIKey.user_id == user_id
        ).order_by(APIKey.created_at.desc())
        
        result = await self.db_session.execute(stmt)
        keys = result.scalars().all()
        
        return [
            {
                "id": key.id,
                "key_id": key.key_id,
                "name": key.name,
                "description": key.description,
                "scopes": key.scopes,
                "is_active": key.is_active,
                "last_used": key.last_used,
                "use_count": key.use_count,
                "expires_at": key.expires_at,
                "created_at": key.created_at,
                "revoked_at": key.revoked_at,
            }
            for key in keys
        ]

# FastAPI依赖项
async def validate_api_key(
    request: Request,
    x_api_key: Optional[str] = Header(None),
    required_scopes: Optional[List[str]] = None,
    db: AsyncSession = Depends(get_db)
) -> APIKey:
    """API密钥验证依赖项"""
    api_key_str = x_api_key
    
    if not api_key_str:
        # 尝试从Authorization头获取
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("ApiKey "):
            api_key_str = auth_header[7:]
    
    if not api_key_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    # 验证API密钥
    api_key_service = APIKeyService(db)
    api_key_record = await api_key_service.validate_key(
        api_key=api_key_str,
        required_scopes=required_scopes,
        client_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent")
    )
    
    if not api_key_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    
    # 将API密钥记录添加到请求状态
    request.state.api_key = api_key_record
    
    return api_key_record