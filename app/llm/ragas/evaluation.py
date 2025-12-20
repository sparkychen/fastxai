# -*- coding: utf-8 -*-

import os
import random
import asyncio
import orjson
from celery import Celery
from datetime import datetime
from pydantic import BaseModel
from fastapi import Request, HTTPException
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from app.core.config import settings
from app.core.logger import logger

# RAG 请求总数
RAG_REQUEST_TOTAL = Counter(
    "rag_request_total", "Total number of RAG requests", ["user_id", "scene", "status"]
)
# RAG 采样总数
RAG_SAMPLE_TOTAL = Counter(
    "rag_sample_total", "Total sampled requests", ["sample_type"]
)
# RAG 响应延迟
RAG_LATENCY = Histogram(
    "rag_latency_seconds", "RAG response latency", ["scene"]
)
# 评估任务投递状态
RAGAS_TASK_TOTAL = Counter(
    "ragas_task_total", "Total RAGAS evaluation tasks", ["status"]
)

# -------------------------- 2. 数据模型定义 --------------------------
class RAGRequest(BaseModel):
    question: str
    user_id: str = None
    scene: str = "default"  # 业务场景（如客服/知识库/电商）
    session_id: str = None

class RAGResponse(BaseModel):
    answer: str
    contexts: list[str]  # RAG 检索的上下文
    reference_answer: str = None  # 可选：人工标注的标准答案
    latency: float  # 在线请求延迟（秒）
    status: str = "success"
    task_id: str = None  # 评估任务 ID（采样后返回）

# -------------------------- 3. Celery 异步任务初始化 --------------------------
celery_app = Celery(
    "ragas_evaluation",
    broker=os.getenv("CELERY_BROKER"),
    backend=os.getenv("CELERY_BACKEND"),
    include=["app.tasks.evaluation"],
    worker_concurrency=int(os.getenv("CELERY_WORKERS", 24)),
    result_expires=3600
)
# 任务配置（生产级）
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_acks_late=True,  # 任务执行完成后确认
    worker_prefetch_multiplier=1,  # 避免任务堆积
    task_queue_max_priority=10,
    task_routes={
        "tasks.evaluation.evaluate_rag": {"queue": "ragas_evaluation"}
    }
)

# 异步投递评估任务函数
async def send_ragas_task(rag_data: dict) -> str:
    """异步投递任务，非阻塞，支持重试"""
    try:
        task = celery_app.send_task(
            "tasks.evaluation.evaluate_rag",
            args=[rag_data],
            queue="ragas_evaluation",
            retry=True,
            retry_policy={
                "max_retries": 3,
                "interval_start": 1,
                "interval_step": 1,
                "interval_max": 5
            }
        )
        RAGAS_TASK_TOTAL.labels(status="success").inc()
        return task.id
    except Exception as e:
        RAGAS_TASK_TOTAL.labels(status="failed").inc()
        print(f"投递评估任务失败: {e}")
        return None

# -------------------------- 4. 采样中间件（核心） --------------------------
async def ragas_middleware(request: Request, call_next):
    start_time = datetime.utcnow()
    response = await call_next(request)
    latency = (datetime.utcnow() - start_time).total_seconds()
    RAG_LATENCY.observe(latency)

    # 仅对 RAG 问答接口采样
    if request.url.path == "/rag/chat" and request.method == "POST":
        try:
            # 解析请求/响应数据
            request_body = await request.json()
            # 从响应中解析 RAG 结果（需根据实际响应格式调整）
            response_body = await response.body()
            rag_response = orjson.loads(response_body)

            # 构建评估所需数据
            scene = request_body.get("scene", "default")
            status = response_body.get("status", "success")
            RAG_REQUEST_TOTAL.labels(scene=scene, status=status).inc()
            RAG_LATENCY.labels(scene=scene).observe(latency)

            rag_data = {
                "question": request_body.get("question"),
                "answer": rag_response.get("answer"),
                "contexts": rag_response.get("contexts"),
                "reference_answer": rag_response.get("reference_answer"),
                "user_id": request_body.get("user_id"),
                "scene": scene,
                "session_id": request_body.get("session_id"),
                "latency": latency,
                "timestamp": datetime.utcnow().isoformat(),
                "status": status,
            }

            # 智能采样规则（三档采样，兼顾覆盖率与资源）
            sample_type = None            
            if latency > float(os.getenv("SAMPLE_ABNORMAL_LATENCY")) or status != "success":
                # 规则 1：异常请求 100% 采样（延迟>800ms 或失败）
                sample_type = "abnormal"            
            elif scene == "core":
                # 规则 2：核心场景 4% 采样
                if random.random() < float(os.getenv("SAMPLE_RATE_CORE_SCENE")):
                    sample_type = "core_scene"            
            else:
                # 规则 3：普通场景 1.5% 随机采样
                if random.random() < float(os.getenv("SAMPLE_RATE_RANDOM")):
                    sample_type = "random"
            # 采样后异步投递任务
            if sample_type:
                RAG_SAMPLE_TOTAL.labels(sample_type=sample_type).inc()
                task_id = await send_ragas_task(rag_data)
                # 将任务 ID 写入响应（方便追踪）
                response_body["task_id"] = task_id
                response.body = orjson.dumps(response_body).encode("utf-8")

            # # 采样规则：1% 随机采样 + 异常请求（延迟>1s/失败）100%采样
            # sample_rate = 0.01
            # is_abnormal = (latency > 1.0) or (rag_response.get("status") != "success")            
            # if random.random() < sample_rate or is_abnormal:
            #     # 记录采样类型
            #     sample_type = "abnormal" if is_abnormal else "random"
            #     RAG_SAMPLE_TOTAL.labels(sample_type=sample_type).inc()
            #     # 异步投递任务（非阻塞）
            #     asyncio.create_task(send_ragas_task(rag_data))
        except Exception as e:
            print(f"Sampling error: {e}")
    return response

from ragas import evaluate
from ragas.metrics import (
    faithfulness,  # 答案与上下文的一致性
    answer_relevancy,  # 答案与问题的相关性
    context_precision,  # 上下文的精准性
    context_recall,  # 上下文的召回率,
    context_entity_recall,
    answer_correctness, # 0.4.1新增
    answer_similarity
)
from ragas.run_config import RunConfig
from ragas.llms import DashScopeLLM
from langchain_community.chat_models import ChatDashScope
llm = DashScopeLLM(
    api_key=os.getenv("RAGAS_LLM_API_KEY"),
    model="qwen-plus",
    temperature=0.0,  # 评估需确定性结果，温度设为0
    max_retries=3,
)
# 1.1 RAGAS 专用 LLM（适配 ragas==0.4.1）
ragas_llm = DashScopeLLM(
    api_key=os.getenv("RAGAS_LLM_API_KEY"),
    model=os.getenv("RAGAS_LLM_MODEL"),
    temperature=0.0,  # 评估需确定性结果
    max_retries=3,
    timeout=30
)

# 1.2 LangChain LLM（用于自定义业务指标计算）
langchain_llm = ChatDashScope(
    api_key=os.getenv("RAGAS_LLM_API_KEY"),
    model=os.getenv("RAGAS_LLM_MODEL"),
    temperature=0.0
)

# 覆盖 RAGAS 原生指标的 LLM
for metric in [faithfulness.llm, answer_relevancy, context_precision, context_recall]:
    metric = ragas_llm

# -------------------------- 2. 自定义业务指标（基于 LangChain 1.0） --------------------------
def calculate_compliance(question: str, answer: str) -> float:
    """
    自定义指标：答案合规性（基于 LangChain LLM 评估）
    :return: 合规性得分（0-1）
    """
    prompt = f"""
    评估以下答案是否符合企业合规要求，仅返回 0-1 之间的数字得分：
    问题：{question}
    答案：{answer}
    合规要求：1. 不泄露敏感信息；2. 不夸大产品功能；3. 语言规范无歧义。
    """
    try:
        result = langchain_llm.invoke(prompt).content
        return round(float(result.strip()), 4)
    except Exception as e:
        print(f"合规性评估失败: {e}")
        return 0.0

# -------------------------- 2. 结果存储初始化（Doris/ClickHouse） --------------------------
# Apache Doris（适配 OLAP 分析）
import MySQLdb
mysql_config = {
    "host": "doris.example.com",
    "port": 9030,
    "user": "root",
    "password": "",
    "database": "your_db",
    "pool_size": 100,  # 企业级推荐值
    "charset": "utf8mb4",
}
client = MySQLdb.connect(**mysql_config)

# 初始化存储表（首次执行）
def init_evaluation_table():
    # ClickHouse 表创建语句（生产级分区+索引）    
    create_table_sql = """
        CREATE TABLE IF NOT EXISTS ragas_evaluation_results (
            question STRING COMMENT '用户问题',
            answer STRING COMMENT 'RAG 生成答案',
            contexts ARRAY<STRING> COMMENT '检索上下文',
            reference_answer STRING,
            user_id STRING COMMENT '用户ID',
            scene STRING COMMENT '业务场景',
            session_id STRING COMMENT '会话ID',
            latency Float64 COMMENT 'RAG 延评估耗时（秒）',
            task_id STRING COMMENT '评估任务ID',
            timestamp DateTime64(6) COMMENT '请求时间',
            status STRING COMMENT 'RAG 状态',
            faithfulness Float64 COMMENT '答案一致性（0-1）',
            answer_relevancy Float64 COMMENT '答案相关性（0-1）',
            context_precision Float64 COMMENT '上下文精准性（0-1）',
            context_recall Float64 COMMENT '上下文召回率（0-1）',
            compliance FLOAT COMMENT '自定义合规性（0-1）'
        ) ENGINE=OLAP
            DUPLICATE KEY(question, task_id)
            DISTRIBUTED BY HASH(task_id) BUCKETS 10
            PROPERTIES (
                'replication_num' = '3',
                'storage_medium' = 'SSD'
            );
    """
    client.command(create_table_sql)
    client.close()

# 存储评估结果
def save_evaluation_result(rag_data: dict, metrics: dict, eval_latency: float):
    """将评估结果写入 OLAP 数据库"""
    try:
        # 构造插入数据
        insert_data = [
            (
                rag_data.get("question"),
                rag_data.get("answer"),
                orjson.dumps(rag_data.get("contexts")),
                rag_data.get("reference_answer") or "",
                rag_data.get("user_id") or "",
                rag_data.get("scene") or "default",
                rag_data.get("session_id") or "",
                rag_data.get("latency", eval_latency),
                rag_data.get("task_id") or "",
                datetime.fromisoformat(rag_data.get("timestamp")),
                rag_data.get("status") or "success",
                metrics.get("faithfulness", 0.0),
                metrics.get("answer_relevancy", 0.0),
                metrics.get("context_precision", 0.0),
                metrics.get("context_recall", 0.0),
                metrics.get("compliance", 0.0)
            )
        ]
        # 批量插入（适配 ragas 批量评估）
        client.insert(
            "ragas_evaluation_results",
            insert_data,
            column_names=[
                "question", "answer", "contexts", "reference_answer",
                "user_id", "scene", "session_id", "latency", "task_id", "timestamp",
                "status", "faithfulness", "answer_relevancy",
                "context_precision", "context_recall", "compliance"
            ],
        )
        client.close()
    except Exception as e:
        print(f"Save result failed: {e}")


# -------------------------- 3. 核心评估任务（ragas==0.4.1 优化） --------------------------
@celery_app.task(name="tasks.evaluate_rag")
def evaluate_rag(rag_data: dict):
    task_id = evaluate_rag.request.id
    rag_data["task_id"] = task_id
    """RAGAS 评估任务（分布式执行）"""
    start_time = datetime.utcnow()
    try:
        # 1. 数据预处理（ragas 要求的格式）
        from datasets import Dataset
        dataset = Dataset.from_dict({
            "question": [rag_data["question"]],
            "answer": [rag_data["answer"]],
            "contexts": [rag_data["contexts"]],
            "reference_answer": [rag_data["reference_answer"]] if rag_data["reference_answer"] else [None],
        })

        # 2. 配置 ragas 运行参数（0.4.1 新增 RunConfig）
        run_config = RunConfig(
            batch_size=int(os.getenv("RAGAS_BATCH_SIZE")),
            cache=os.getenv("RAGAS_CACHE_ENABLE", "True") == "True",  # 启用缓存
            cache_folder="/tmp/ragas_cache",  # 缓存目录（持久化）
        )

        # 3. 执行评估（选择核心指标，减少计算量）
        metrics_to_evaluate = [
            faithfulness,
            answer_relevancy,
            context_recall,
            context_precision,
            answer_correctness,
            answer_similarity,
            context_entity_recall,
        ]
        
        # 创建评估器（关键优化！）
        result = evaluate(
            dataset=dataset,
            metrics=metrics_to_evaluate,
            llm=llm,
            run_config=run_config,
            raise_exceptions=True,
            show_progress=True,
            # 0.4.1新增：批量处理优化
            batch_size=50,  # 从0.3.0的20提升到50
        )

        # 4. 解析评估结果
        metrics = result.to_dict()["scores"]
        eval_latency = (datetime.utcnow() - start_time).total_seconds()        

        # 5. 存储结果
        save_evaluation_result(rag_data, metrics, eval_latency)

        return {
            "status": "success",
            "metrics": metrics,
            "eval_latency": eval_latency,
        }
    except Exception as e:
        print(f"Evaluation failed: {e}")
        # 记录失败结果（便于排查）
        save_evaluation_result(
            rag_data,
            metrics={"faithfulness": 0.0, "answer_relevancy": 0.0, "context_precision": 0.0, "context_recall": 0.0},
            eval_latency=(datetime.utcnow() - start_time).total_seconds(),
        )
        raise e
    
# 初始化评估表（首次启动执行）
init_evaluation_table()

# Grafana看板模板（企业级核心）：
# 指标	企业级阈值	业务价值
# rag_faithfulness	≥ 0.85	保证答案事实准确率
# rag_answer_relevancy	≥ 0.90	确保回答直接解决问题
# rag_answer_correctness	≥ 0.88	业务答案正确率（0.4.1新增）
# rag_context_recall	≥ 0.80	关键信息检索覆盖率
# rag_latency_ms	≤ 50ms	用户无感知延迟
# rag_eval_throughput	≥ 1000 QPS	评估系统吞吐能力


# 生成高质量测试集（从生产数据中自动扩展）
import ragas
def generate_test_set(data):
    # 使用Ragas的自动测试生成能力
    test_set = ragas.generate_test_set(
        data,
        num_samples=1000,  # 生成1000个样本
        include_context=True,
        include_ground_truth=True
    )
    return test_set