# -*- coding: utf-8 -*-

from sqlalchemy import Column, DateTime, Integer, func
from sqlalchemy.dialects.postgresql import UUID
from app.database.postgres import Base
import uuid
from uuid_extensions import uuid7
from sqlmodel import SQLModel, Field, DateTime

class BaseModel(SQLModel):
    """企业级基础模型（含审计、软删除）"""
    __abstract__ = True

    # 主键：UUID（避免自增ID性能瓶颈）
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid7(), index=True)
    # 审计字段（合规要求）
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False, index=True)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
    created_by = Column(UUID(as_uuid=True), nullable=True, index=True)  # 创建人ID
    updated_by = Column(UUID(as_uuid=True), nullable=True)             # 更新人ID
    # 软删除（企业级必备，避免数据丢失）
    is_deleted = Column(Integer, default=0, nullable=False, index=True)  # 0=正常，1=删除

    # 性能优化：批量插入忽略重复
    __table_args__ = ({"extend_existing": True},)

    def to_dict(self) -> dict:
        """模型转字典（基础序列化）"""
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
