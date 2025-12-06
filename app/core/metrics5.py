# -*- coding: utf-8 -*-

from prometheus_client import Counter, Gauge, Histogram

# 认证相关指标
AUTH_COUNTER = Counter(
    "fastapi_users_auth_total",
    "Total number of authentication events",
    ["event_type"]
)
AUTH_GAUGE = Gauge(
    "fastapi_users_cache_status",
    "Cache status metrics",
    ["status"]
)
AUTH_HISTOGRAM = Histogram(
    "fastapi_users_response_time_seconds",
    "Response time for auth endpoints",
    ["endpoint"]
)

def increment_auth_metric(event_type: str):
    """递增认证计数器"""
    AUTH_COUNTER.labels(event_type=event_type).inc()

def set_cache_gauge(status: str, value: float):
    """设置缓存指标"""
    AUTH_GAUGE.labels(status=status).set(value)

def observe_response_time(endpoint: str, duration: float):
    """记录响应时间"""
    AUTH_HISTOGRAM.labels(endpoint=endpoint).observe(duration)
