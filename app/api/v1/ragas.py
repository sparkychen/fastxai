# -*- coding: utf-8 -*-

from datetime import datetime
from app.llm.ragas.evaluation import ragas_middleware, RAGResponse, RAGRequest, RAG_REQUEST_TOTAL, generate_latest, CONTENT_TYPE_LATEST
from fastapi import APIRouter, Depends, Request
from app.core.logger import logger


router = APIRouter(prefix="/ragas", tags=["llm_ragas_evaluation"])

@router.post("/rag/chat", response_model=RAGResponse)
async def rag_chat(request: RAGRequest):
    # 记录请求数
    RAG_REQUEST_TOTAL.labels(user_id=request.user_id, scene=request.scene).inc()
    
    # -------------------------- 此处为你的在线 RAG 核心逻辑 --------------------------
    # 示例：检索上下文 + 调用 LLM 生成答案
    contexts = ["上下文1：企业级 RAG 性能评估需异步采样", "上下文2：ragas 0.4.1 支持批量评估"]
    answer = "RAG 性能评估需采用异步采样方式，避免影响在线服务"
    reference_answer = None  # 生产中可从知识库获取标准答案
    # ------------------------------------------------------------------------------
    
    return RAGResponse(
        answer=answer,
        contexts=contexts,
        reference_answer=reference_answer,
        latency=(datetime.utcnow() - datetime.utcnow()).total_seconds(),  # 实际需计算真实延迟
    )

# -------------------------- 6. 监控接口 --------------------------
@router.get("/metrics")
async def metrics():
    return generate_latest(), 200, {"Content-Type": CONTENT_TYPE_LATEST}