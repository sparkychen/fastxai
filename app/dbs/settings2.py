# -*- coding: utf-8 -*-

# 数据库配置示例（建议用pydantic-settings管理）
from pydantic import PostgresDsn
from typing import List, Literal

class DBSettings:
    # 主库（写）DSN
    db_write_dsn: PostgresDsn = "postgresql+asyncpg://user:pass@master-db:5432/db"
    # 从库（读）DSN列表（读写分离）
    db_read_dsns: List[PostgresDsn] = ["postgresql+asyncpg://user:pass@slave1-db:5432/db", "postgresql+asyncpg://user:pass@slave2-db:5432/db"]
    # 读写分离开关
    db_enable_rw_separation: bool = True
    # 连接池配置
    db_pool_size: int = 20          # 常驻连接数（CPU核心*2）
    db_max_overflow: int = 40       # 溢出连接数（应急）
    db_pool_recycle: int = 280      # 连接回收时间（<300s，避免数据库超时）
    db_connect_timeout: int = 10    # 连接超时
    db_charset: str = "utf8mb4"     # 字符集
    # 日志/调试
    db_echo: bool = False           # 生产环境关闭SQL打印
    # 环境
    env: Literal["development", "production"] = "production"

settings = DBSettings()
