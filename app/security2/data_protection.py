# -*- coding: utf-8 -*-

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import re
from typing import Dict, Any, Optional
from app.security.sc_config import security_settings
import structlog

logger = structlog.get_logger()

# ================= 1. 对称加密（AES-256-GCM） =================
class AESCrypto:
    """AES-256-GCM加密（支持认证和完整性校验）"""
    def __init__(self):
        self.key = security_settings.ENCRYPTION_KEY
        self.backend = default_backend()

    def encrypt(self, plaintext: str) -> str:
        """加密明文（返回base64编码的密文+nonce+tag）"""
        # 生成随机nonce（12字节）
        nonce = os.urandom(12)
        # 创建加密器
        cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        # 加密
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        # 获取认证标签
        tag = encryptor.tag
        # 拼接nonce + tag + ciphertext，base64编码
        encrypted = base64.b64encode(nonce + tag + ciphertext).decode()
        return encrypted

    def decrypt(self, ciphertext: str) -> str:
        """解密密文"""
        try:
            # 解码
            data = base64.b64decode(ciphertext)
            # 拆分nonce(12) + tag(16) + ciphertext
            nonce = data[:12]
            tag = data[12:28]
            ciphertext = data[28:]
            # 创建解密器
            cipher = Cipher(algorithms.AES(self.key), modes.GCM(nonce, tag), backend=self.backend)
            decryptor = cipher.decryptor()
            # 解密
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            return plaintext.decode()
        except Exception as e:
            logger.error("AES decryption failed", error=str(e))
            raise ValueError("Invalid ciphertext or key")

# ================= 2. 数据脱敏 =================
class DataMasker:
    """敏感数据脱敏"""
    @staticmethod
    def mask_field(field_name: str, value: Any) -> Any:
        """根据字段名脱敏"""
        if field_name not in security_settings.SENSITIVE_FIELDS or not value:
            return value
        
        value_str = str(value)
        
        # 邮箱脱敏：user***@domain.com
        if field_name == "email":
            match = re.match(r"^(.+?)@(.+)$", value_str)
            if match:
                return f"{match.group(1)[:3]}***@{match.group(2)}"
        
        # 手机号脱敏：138****1234
        elif field_name == "phone":
            if len(value_str) == 11:
                return f"{value_str[:3]}****{value_str[-4:]}"
        
        # 身份证脱敏：110**********1234
        elif field_name == "id_card":
            if len(value_str) == 18:
                return f"{value_str[:3]}**********{value_str[-4:]}"
        
        # 银行卡脱敏：6226****1234
        elif field_name == "bank_card":
            if len(value_str) >= 8:
                return f"{value_str[:4]}****{value_str[-4:]}"
        
        # 通用脱敏：保留前3后2，中间替换
        else:
            if len(value_str) > 5:
                return f"{value_str[:3]}{security_settings.DATA_MASKING_CHAR * (len(value_str)-5)}{value_str[-2:]}"
            else:
                return security_settings.DATA_MASKING_CHAR * len(value_str)

    @staticmethod
    def mask_dict(data: Dict[str, Any]) -> Dict[str, Any]:
        """脱敏字典中的敏感字段"""
        masked = {}
        for key, value in data.items():
            masked[key] = DataMasker.mask_field(key, value)
        return masked

# ================= 3. 输入验证（增强Pydantic） =================
from pydantic import field_validator, ValidationInfo
from pydantic_core import PydanticCustomError

def validate_sensitive_input(value: str, field_name: str) -> str:
    """验证敏感输入（防注入）"""
    # 防SQL注入基础规则
    sql_injection_patterns = [
        r"('|\").*;.*(DROP|ALTER|INSERT|SELECT|UPDATE|DELETE)",
        r"OR\s+1=1",
        r"UNION\s+SELECT",
    ]
    for pattern in sql_injection_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            raise PydanticCustomError(
                "invalid_input",
                f"Invalid input for {field_name}: potential SQL injection"
            )
    # 防XSS基础规则
    xss_patterns = [r"<script.*?>.*?</script>", r"javascript:", r"onload=", r"onclick="]
    for pattern in xss_patterns:
        if re.search(pattern, value, re.IGNORECASE):
            raise PydanticCustomError(
                "invalid_input",
                f"Invalid input for {field_name}: potential XSS attack"
            )
    return value

# 初始化工具
aes_crypto = AESCrypto()
data_masker = DataMasker()
