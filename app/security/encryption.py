# -*- coding: utf-8 -*-

import os
from typing import Any, Dict, Optional
from cryptography.fernet import Fernet, MultiFernet
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import json
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import TypeDecorator, String
import structlog

logger = structlog.get_logger()

class DataEncryptor:
    """数据加密器"""
    
    def __init__(self, encryption_key: Optional[str] = None):
        self.encryption_key = encryption_key or security_settings.ENCRYPTION_KEY
        
        # 生成密钥派生
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"fastapi_secure_salt",
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.encryption_key.encode()))
        
        # 创建多Fernet实例以支持密钥轮换
        self.fernet = Fernet(key)
    
    def encrypt_field(self, data: Any) -> str:
        """加密字段数据"""
        if data is None:
            return None
        
        # 序列化数据
        if isinstance(data, (dict, list)):
            data_str = json.dumps(data)
        else:
            data_str = str(data)
        
        # 加密
        encrypted_data = self.fernet.encrypt(data_str.encode())
        
        # 返回Base64编码的加密数据
        return base64.urlsafe_b64encode(encrypted_data).decode()
    
    def decrypt_field(self, encrypted_data: str) -> Any:
        """解密字段数据"""
        if not encrypted_data:
            return None
        
        try:
            # Base64解码
            encrypted_bytes = base64.urlsafe_b64decode(encrypted_data)
            
            # 解密
            decrypted_bytes = self.fernet.decrypt(encrypted_bytes)
            decrypted_str = decrypted_bytes.decode()
            
            # 尝试反序列化JSON
            try:
                return json.loads(decrypted_str)
            except json.JSONDecodeError:
                return decrypted_str
        
        except Exception as e:
            logger.error("Failed to decrypt field", error=str(e))
            raise ValueError("Decryption failed")
    
    def encrypt_sensitive_data(self, data: Dict[str, Any], fields_to_encrypt: list) -> Dict[str, Any]:
        """加密敏感数据字典"""
        encrypted_data = data.copy()
        
        for field in fields_to_encrypt:
            if field in encrypted_data and encrypted_data[field] is not None:
                encrypted_data[field] = self.encrypt_field(encrypted_data[field])
        
        return encrypted_data
    
    def decrypt_sensitive_data(self, encrypted_data: Dict[str, Any], fields_to_decrypt: list) -> Dict[str, Any]:
        """解密敏感数据字典"""
        decrypted_data = encrypted_data.copy()
        
        for field in fields_to_decrypt:
            if field in decrypted_data and decrypted_data[field] is not None:
                decrypted_data[field] = self.decrypt_field(decrypted_data[field])
        
        return decrypted_data

class EncryptedString(TypeDecorator):
    """SQLAlchemy加密字符串类型装饰器"""
    
    impl = String
    cache_ok = True
    
    def __init__(self, length: int = 2048, *args, **kwargs):
        super().__init__(length, *args, **kwargs)
        self.encryptor = DataEncryptor()
    
    def process_bind_param(self, value, dialect):
        """在绑定到数据库时加密"""
        if value is not None:
            return self.encryptor.encrypt_field(value)
        return value
    
    def process_result_value(self, value, dialect):
        """从数据库读取时解密"""
        if value is not None:
            return self.encryptor.decrypt_field(value)
        return value
    
    def copy(self, **kw):
        """创建副本"""
        return EncryptedString(self.impl.length)

class DatabaseEncryptionService:
    """数据库加密服务"""
    
    SENSITIVE_FIELDS = {
        'users': ['ssn', 'phone_number', 'address', 'payment_info'],
        'api_keys': ['secret_key_hash'],
        'audit_logs': ['event_data', 'metadata'],
        'transactions': ['amount', 'currency', 'payment_details'],
    }
    
    def __init__(self, db_session: AsyncSession):
        self.db_session = db_session
        self.encryptor = DataEncryptor()
    
    async def encrypt_database_field(
        self,
        table_name: str,
        record_id: str,
        field_name: str,
        value: Any
    ) -> bool:
        """加密数据库字段"""
        try:
            # 检查是否为敏感字段
            if table_name not in self.SENSITIVE_FIELDS:
                logger.warning(f"Table {table_name} not configured for encryption")
                return False
            
            if field_name not in self.SENSITIVE_FIELDS[table_name]:
                logger.warning(f"Field {field_name} not configured for encryption in table {table_name}")
                return False
            
            # 加密值
            encrypted_value = self.encryptor.encrypt_field(value)
            
            # 更新数据库
            from sqlalchemy import text
            query = text(f"""
                UPDATE {table_name} 
                SET {field_name} = :encrypted_value
                WHERE id = :record_id
            """)
            
            await self.db_session.execute(
                query,
                {"encrypted_value": encrypted_value, "record_id": record_id}
            )
            
            await self.db_session.commit()            
            logger.info(
                "Field encrypted successfully",
                table=table_name,
                field=field_name,
                record_id=record_id
            )            
            return True
        
        except Exception as e:
            logger.error(
                "Failed to encrypt field",
                table=table_name,
                field=field_name,
                record_id=record_id,
                error=str(e)
            )
            await self.db_session.rollback()
            return False
    
    async def batch_encrypt_table(self, table_name: str):
        """批量加密表中的敏感字段"""
        if table_name not in self.SENSITIVE_FIELDS:
            logger.warning(f"Table {table_name} not configured for encryption")
            return
        
        fields_to_encrypt = self.SENSITIVE_FIELDS[table_name]
        
        try:
            # 获取所有记录
            from sqlalchemy import text, inspect
            inspector = inspect(self.db_session.bind)
            columns = [col['name'] for col in inspector.get_columns(table_name)]
            
            if 'id' not in columns:
                logger.error(f"Table {table_name} has no id column")
                return
            
            # 分批处理
            batch_size = 100
            offset = 0
            
            while True:
                # 查询一批记录
                query = text(f"""
                    SELECT id, {', '.join(fields_to_encrypt)}
                    FROM {table_name}
                    ORDER BY id
                    LIMIT {batch_size} OFFSET {offset}
                """)
                
                result = await self.db_session.execute(query)
                records = result.fetchall()
                
                if not records:
                    break
                
                # 加密并更新
                for record in records:
                    record_id = record[0]
                    update_values = {}
                    
                    for i, field in enumerate(fields_to_encrypt, 1):
                        value = record[i]
                        if value and not self._is_encrypted(value):
                            encrypted_value = self.encryptor.encrypt_field(value)
                            update_values[field] = encrypted_value
                    
                    if update_values:
                        set_clause = ', '.join([f"{k} = :{k}" for k in update_values.keys()])
                        update_query = text(f"""
                            UPDATE {table_name}
                            SET {set_clause}
                            WHERE id = :record_id
                        """)
                        
                        params = update_values.copy()
                        params['record_id'] = record_id
                        
                        await self.db_session.execute(update_query, params)
                
                await self.db_session.commit()
                offset += batch_size
                
                logger.info(
                    f"Batch encrypted {len(records)} records from {table_name}",
                    offset=offset
                )
            
            logger.info(f"Table {table_name} encryption completed")
        
        except Exception as e:
            logger.error(f"Failed to batch encrypt table {table_name}", error=str(e))
            await self.db_session.rollback()
    
    def _is_encrypted(self, value: str) -> bool:
        """检查值是否已加密"""
        try:
            if not isinstance(value, str):
                return False
            
            # 尝试Base64解码
            decoded = base64.urlsafe_b64decode(value)
            
            # 检查是否为有效的加密数据
            return len(decoded) > 0
        
        except Exception:
            return False
    
    def rotate_encryption_key(self, new_key: str):
        """轮换加密密钥"""
        # 创建新的加密器
        new_encryptor = DataEncryptor(new_key)
        
        # 这里可以实现密钥轮换逻辑
        # 1. 使用新密钥重新加密所有数据
        # 2. 更新密钥存储
        # 3. 废弃旧密钥
        
        logger.info("Encryption key rotation initiated")
        
        return new_encryptor