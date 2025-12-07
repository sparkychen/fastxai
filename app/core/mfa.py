# -*- coding: utf-8 -*-

import pyotp
import qrcode

users = {}

# ========== 步骤1：用户注册/绑定 MFA 时，生成唯一种子密钥 ==========
def create_mfa_secret(user_id: str) -> str:
    # 生成16位种子密钥（与用户ID绑定，存储到数据库）
    username = request.json['username']
    secret = pyotp.random_base32()
    users[username] = {'secret': secret}

    # 生成一个用于二维码的链接，方便用户绑定
    totp = pyotp.TOTP(secret)
    # 可选：存储到数据库（user_id -> secret）
    # db.execute("UPDATE users SET mfa_secret = %s WHERE id = %s", (secret, user_id))
    return secret

# ========== 步骤2：生成二维码（用户扫码绑定到谷歌验证器） ==========
def generate_mfa_qrcode(user_id: str, secret: str, issuer_name: str = "企业系统") -> None:
    # 构建谷歌验证器兼容的 URI
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(
        name=user_id,  # 用户名/邮箱
        issuer_name=issuer_name  # 系统名称（显示在验证器中）
    )
    # 生成二维码图片（用户扫码即可绑定）
    qr = qrcode.make(uri)
    qr.save(f"{user_id}_mfa_qrcode.png")
    print(f"请扫码绑定 MFA：{user_id}_mfa_qrcode.png")

# ========== 步骤3：用户登录时，验证「密码 + MFA 动态码」 ==========
def verify_mfa_code(secret: str, user_input_code: str) -> bool:
    # 初始化 TOTP 验证器（30秒有效期）
    totp = pyotp.TOTP(secret)
    # 验证动态码（允许1个时间窗口误差，即±30秒，避免网络延迟）
    return totp.verify(user_input_code, valid_window=1)

# ========== 测试流程 ==========
if __name__ == "__main__":
    # 模拟用户ID
    user_id = "user123@example.com"
    
    # 1. 绑定 MFA：生成密钥 + 二维码
    secret = create_mfa_secret(user_id)
    print("MFA 种子密钥（备份用）：", secret)
    generate_mfa_qrcode(user_id, secret)
    
    # 2. 登录验证：用户输入谷歌验证器的6位动态码
    user_input_code = input("请输入谷歌验证器的6位动态码：")
    if verify_mfa_code(secret, user_input_code):
        print("MFA 验证通过！登录成功")
    else:
        print("MFA 验证失败！动态码错误/过期")
