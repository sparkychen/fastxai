# -*- coding: utf-8 -*-

import time
import psutil
from prometheus_client import Counter, Histogram, Gauge
import sentry_sdk
from typing import Callable

# Prometheus 指标
REQUEST_COUNT = Counter('http_requests_total', 'Total HTTP Requests', ['method', 'endpoint', 'status'])
REQUEST_DURATION = Histogram('http_request_duration_seconds', 'HTTP request duration', ['endpoint'])
MEMORY_USAGE = Gauge('memory_usage_bytes', 'Memory usage in bytes')

def monitor_performance(endpoint: str):
    """性能监控装饰器"""
    def decorator(func: Callable):
        async def wrapper(*args, **kwargs):
            start_time = time.time()
            
            with sentry_sdk.start_span(op="http", description=endpoint) as span:
                try:
                    result = await func(*args, **kwargs)
                    duration = time.time() - start_time
                    
                    # 记录指标
                    REQUEST_DURATION.labels(endpoint=endpoint).observe(duration)
                    REQUEST_COUNT.labels(
                        method=kwargs.get('method', 'GET'),
                        endpoint=endpoint,
                        status=200
                    ).inc()
                    
                    # 设置性能数据
                    span.set_data("duration", duration)
                    span.set_tag("endpoint", endpoint)
                    span.set_status("ok")
                    
                    return result
                    
                except Exception as e:
                    duration = time.time() - start_time
                    REQUEST_COUNT.labels(
                        method=kwargs.get('method', 'GET'),
                        endpoint=endpoint,
                        status=500
                    ).inc()
                    
                    span.set_tag("error", True)
                    span.set_status("internal_error")
                    raise
        
        return wrapper
    return decorator

async def collect_system_metrics():
    """收集系统指标并发送到 Sentry"""
    # 内存使用情况
    memory = psutil.virtual_memory()
    MEMORY_USAGE.set(memory.used)
    
    # 可以定期将系统指标发送到 Sentry
    sentry_sdk.set_context("system", {
        "memory_used": memory.used,
        "memory_percent": memory.percent,
        "cpu_percent": psutil.cpu_percent(),
    })