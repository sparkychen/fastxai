# -*- coding: utf-8 -*-

import os
import re
import html
from typing import Any, Optional, List, Dict
from pydantic import EmailStr, constr, conint, confloat, Field, field_validator, BaseModel, StringConstraints
from app.core.config import settings
from typing import Annotated
import bleach

class SecureString(str):
    """安全字符串类，自动处理XSS"""    
    def __new__(cls, value: Any):
        if value is None:
            value = ""
        # 自动HTML转义
        safe_value = html.escape(str(value))
        return super().__new__(cls, safe_value)

class SanitizedInput(BaseModel):
    """基础安全输入模型"""    
    class Config:
        anystr_strip_whitespace = True
        validate_assignment = True
    
    @field_validator('*', pre=True)
    def sanitize_strings(cls, v):
        """消毒字符串输入"""
        if isinstance(v, str):
            # 移除不可见字符
            v = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', v)
            # 限制长度
            if hasattr(cls, '__fields__'):
                field_info = cls.__fields__.get(cls.__fields__[cls.__fields__['__all_fields_index__'][0]].name)
                if field_info and hasattr(field_info, 'field_info') and field_info.field_info.max_length:
                    max_len = field_info.field_info.max_length
                    if len(v) > max_len:
                        v = v[:max_len]
        return v

class UserInput(SanitizedInput):
    """用户输入模型"""
    username: Annotated[
        str, 
        StringConstraints(
            min_length=3, 
            max_length=50, 
            pattern=r'^[a-zA-Z0-9_.-]+$'
        )
    ]
    email: EmailStr
    password: Annotated[
        str, 
        StringConstraints(
            min_length=12, 
            max_length=128
        )
    ]
    
    @field_validator('username')
    def validate_username(cls, v):
        """验证用户名"""
        # 防止注入攻击
        blacklist = ['admin', 'root', 'system', 'null', 'undefined']
        if v.lower() in blacklist:
            raise ValueError('Username not allowed')
        return v
    
    @field_validator('password')
    def validate_password(cls, v):
        """验证密码强度"""
        from .auth import auth_service
        if not auth_service.validate_password_policy(v):
            raise ValueError(
                f'Password must be at least {settings.PASSWORD_MIN_LENGTH} '
                'characters and contain uppercase, lowercase, digit, and special character'
            )
        return v

class SQLSafeString(str):
    """SQL安全字符串"""
    
    SQL_KEYWORDS = [
        'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'DROP', 'CREATE', 'ALTER',
        'TRUNCATE', 'EXEC', 'EXECUTE', 'UNION', 'OR', 'AND', 'LIKE'
    ]
    
    def __new__(cls, value: str):
        # 检查SQL注入
        upper_value = value.upper()
        for keyword in cls.SQL_KEYWORDS:
            pattern = rf'\b{keyword}\b'
            if re.search(pattern, upper_value):
                raise ValueError(f'Potential SQL injection detected: {keyword}')
        return super().__new__(cls, value)

class HTMLSanitizer:
    """HTML消毒器"""
    
    ALLOWED_TAGS = [
        'a', 'abbr', 'acronym', 'b', 'blockquote', 'code', 'em', 'i', 
        'li', 'ol', 'strong', 'ul', 'p', 'br', 'span', 'div',
        'h1', 'h2', 'h3', 'h4', 'h5', 'h6'
    ]
    
    ALLOWED_ATTRIBUTES = {
        'a': ['href', 'title', 'target'],
        'abbr': ['title'],
        'acronym': ['title'],
        '*': ['class', 'id', 'style']
    }
    
    ALLOWED_STYLES = [
        'color', 'background-color', 'font-weight', 'font-style',
        'text-decoration', 'text-align'
    ]
    
    @staticmethod
    def sanitize(html_content: str) -> str:
        """消毒HTML内容"""
        if not html_content:
            return ""
        
        # 使用bleach进行消毒
        sanitized = bleach.clean(
            html_content,
            tags=HTMLSanitizer.ALLOWED_TAGS,
            attributes=HTMLSanitizer.ALLOWED_ATTRIBUTES,
            styles=HTMLSanitizer.ALLOWED_STYLES,
            strip=True,
            strip_comments=True
        )
        
        # 移除危险属性
        sanitized = re.sub(r'on\w+\s*=\s*"[^"]*"', '', sanitized)
        sanitized = re.sub(r'on\w+\s*=\s*\'[^\']*\'', '', sanitized)
        sanitized = re.sub(r'on\w+\s*=\s*[^\s>]*', '', sanitized)
        
        # 移除javascript:协议
        sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    @staticmethod
    def validate_url(url: str) -> bool:
        """验证URL安全性"""
        if not url:
            return False
        
        # 允许的协议
        allowed_protocols = ['http:', 'https:', 'mailto:', 'tel:']
        
        try:
            from urllib.parse import urlparse
            parsed = urlparse(url)
            
            if parsed.scheme not in allowed_protocols:
                return False
            
            # 检查危险字符
            if re.search(r'[\x00-\x1F\x7F]', url):
                return False
            
            return True
        except Exception:
            return False

class InputValidationService:
    """输入验证服务"""    
    @staticmethod
    def validate_email(email: str) -> bool:
        """验证邮箱格式和安全性"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        
        if not re.match(email_pattern, email):
            return False
        
        # 防止邮箱注入
        if re.search(r'[\r\n]', email):
            return False
        
        # 检查常见攻击模式
        attack_patterns = [
            r'\.\.\/',  # 目录遍历
            r'<script',  # 脚本标签
            r'javascript:',  # JavaScript协议
        ]
        
        for pattern in attack_patterns:
            if re.search(pattern, email, re.IGNORECASE):
                return False
        
        return True
    
    @staticmethod
    def validate_phone(phone: str) -> bool:
        """验证电话号码"""
        # 简单验证，可根据需求扩展
        phone_pattern = r'^[\+]?[1-9][0-9 \-\(\)\.]{7,}$'
        return bool(re.match(phone_pattern, phone))
    
    @staticmethod
    def sanitize_input(input_data: Any) -> Any:
        """消毒输入数据"""
        if isinstance(input_data, str):
            # HTML转义
            input_data = html.escape(input_data)
            
            # 移除控制字符
            input_data = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', input_data)
            
            # 限制长度（防止缓冲区溢出）
            if len(input_data) > 10000:
                input_data = input_data[:10000]
        
        elif isinstance(input_data, dict):
            return {k: InputValidationService.sanitize_input(v) for k, v in input_data.items()}
        
        elif isinstance(input_data, list):
            return [InputValidationService.sanitize_input(item) for item in input_data]
        
        return input_data
    
    @staticmethod
    def validate_file_upload(filename: str, content_type: str, max_size: int = 10485760) -> bool:
        """验证文件上传安全性"""
        # 允许的文件扩展名
        allowed_extensions = {
            'image': ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'],
            'document': ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt'],
            'archive': ['.zip', '.rar', '.7z', '.tar', '.gz'],
        }
        
        # 允许的MIME类型
        allowed_mime_types = [
            'image/jpeg', 'image/png', 'image/gif', 'image/bmp', 'image/webp',
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/vnd.ms-powerpoint',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'text/plain',
            'application/zip', 'application/x-rar-compressed', 'application/x-7z-compressed',
            'application/x-tar', 'application/gzip',
        ]
        
        # 检查文件扩展名
        ext = os.path.splitext(filename)[1].lower()
        
        valid_extension = False
        for category, extensions in allowed_extensions.items():
            if ext in extensions:
                valid_extension = True
                break
        
        if not valid_extension:
            return False
        
        # 检查MIME类型
        if content_type not in allowed_mime_types:
            return False
        
        # 检查文件名安全性
        if re.search(r'[\/\\:\*\?"<>\|]', filename):
            return False
        
        # 防止路径遍历
        if '..' in filename:
            return False
        
        return True

# 快速验证装饰器
def validate_input(model_class):
    """输入验证装饰器"""
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # 验证输入参数
            for arg_name, arg_value in kwargs.items():
                if isinstance(arg_value, str):
                    # 自动消毒字符串输入
                    kwargs[arg_name] = InputValidationService.sanitize_input(arg_value)
            
            return await func(*args, **kwargs)
        return wrapper
    return decorator