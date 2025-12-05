# -*- coding: utf-8 -*-
# doubao

import uuid
import hashlib
import hmac
import re
from typing import Dict, Any, Optional
from app.core.config import audit_settings

# ========== 敏感数据脱敏 ==========
def mask_sensitive_data(data: Any) -> Any:
    """递归脱敏敏感字段"""
    if isinstance(data, dict):
        masked = {}
        for key, value in data.items():
            if key.lower() in audit_settings.AUDIT_LOG_SENSITIVE_FIELDS:
                masked[key] = mask_field(key, value)
            else:
                masked[key] = mask_sensitive_data(value)
        return masked
    elif isinstance(data, list):
        return [mask_sensitive_data(item) for item in data]
    return data

def mask_field(field_name: str, value: Any) -> str:
    """按字段类型脱敏"""
    if not value:
        return ""
    
    value_str = str(value).strip()
    field_name = field_name.lower()
    
    # 密码：全脱敏
    if "password" in field_name or "token" in field_name:
        return "***"
    
    # 手机号：138****1234
    if "phone" in field_name and len(value_str) == 11 and value_str.isdigit():
        return f"{value_str[:3]}****{value_str[-4:]}"
    
    # 身份证：110**********1234
    if "id_card" in field_name and len(value_str) == 18:
        return f"{value_str[:3]}**********{value_str[-4:]}"
    
    # 银行卡：6226****1234
    if "bank_card" in field_name and len(value_str) >= 8:
        return f"{value_str[:4]}****{value_str[-4:]}"
    
    # 邮箱：user***@domain.com
    if "email" in field_name:
        match = re.match(r"^(.+?)@(.+)$", value_str)
        if match:
            return f"{match.group(1)[:3]}***@{match.group(2)}"
    
    # 通用脱敏：保留前3后2，中间替换为*
    if len(value_str) > 5:
        return f"{value_str[:3]}***{value_str[-2:]}"
    return "***"

# ========== 审计日志签名（防篡改） ==========
def sign_audit_log(log_data: Dict[str, Any]) -> str:
    """生成审计日志签名（HMAC-SHA256）"""
    if not audit_settings.AUDIT_LOG_SIGN_ENABLE:
        return ""
    
    # 提取签名字段（排序保证一致性）
    sign_fields = sorted([
        (k, v) for k, v in log_data.items()
        if k not in ["signature", "error_msg"]  # 排除可变字段
    ])
    # 序列化签名内容
    sign_content = json.dumps(sign_fields, sort_keys=True, default=str).encode()
    # 生成HMAC签名
    signature = hmac.new(
        audit_settings.AUDIT_LOG_SIGN_SECRET,
        sign_content,
        hashlib.sha256
    ).hexdigest()
    return signature

# ========== 审计日志验证 ==========
def verify_audit_log(log_data: Dict[str, Any]) -> bool:
    """验证审计日志签名（防篡改）"""
    if not audit_settings.AUDIT_LOG_SIGN_ENABLE:
        return True
    
    original_sign = log_data.get("signature", "")
    if not original_sign:
        return False
    
    # 移除签名后重新计算
    log_data_copy = log_data.copy()
    del log_data_copy["signature"]
    new_sign = sign_audit_log(log_data_copy)
    return hmac.compare_digest(original_sign, new_sign)
