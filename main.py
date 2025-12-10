
# -*- coding: utf-8 -*-

import os
import sys
import uvicorn
from app.core.config import settings
import multiprocessing
from uuid_extensions import uuid7
import secrets

def get_cpu_cores():
    try:
        # Linux/Mac
        return multiprocessing.cpu_count()
    except:
        return 4

if __name__ == "__main__":
    uvicorn_config = {
        "host": settings.APP_HOST,
        "port": settings.APP_PORT,
        "reload": settings.DEBUG,
        "workers": 1,  # 多worker处理
        "proxy_headers": True,  # 支持代理头
        "forwarded_allow_ips": "*", 
        "timeout_keep_alive": 30,
        "timeout_graceful_shutdown": 30,
        "log_level": settings.LOG_LEVEL.lower(),
        "access_log": False,
        "log_config": None,
        "reload_dirs": ["app"],
        "reload_excludes": ["*.tmp", "*.log", "*.err", "tests/*"],
    }
    if sys.platform == "linux":
        CPU_CORES = get_cpu_cores()
        uvicorn_config["loop"] = "uvloop"
        uvicorn_config["workers"] = 4
        uvicorn_config["http"] = "httptools"
    
    uvicorn.run("app.main:app", **uvicorn_config)
