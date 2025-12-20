# -*- coding: utf-8 -*-

import os
from dotenv import load_dotenv
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.runnables import RunnablePassthrough, RunnableParallel
from langchain_core.output_parsers import StrOutputParser
from langchain_core.cache import RedisCache
from langchain_community.cache import RedisSemanticCache
from langchain_community.vectorstores import Milvus
from langchain_community.embeddings import DashScopeEmbeddings
from langchain_community.chat_models import ChatDashScope

# 加载配置
load_dotenv()

# -------------------------- 1. 初始化基础组件（LangChain 1.0） --------------------------
# 1.1 嵌入模型（通义千问）
embeddings = DashScopeEmbeddings(
    api_key=os.getenv("RAGAS_LLM_API_KEY"),
    model="text-embedding-v1"
)

# 1.2 向量存储（Milvus）
vectorstore = Milvus(
    embedding_function=embeddings,
    collection_name=os.getenv("MILVUS_COLLECTION"),
    connection_args={"host": os.getenv("MILVUS_HOST"), "port": os.getenv("MILVUS_PORT")},
)
retriever = vectorstore.as_retriever(search_kwargs={"k": 4})  # 检索 Top4 上下文

# 1.3 LLM 模型（私有化通义千问 V4，LangChain 1.0 原生集成）
llm = ChatDashScope(
    api_key=os.getenv("RAGAS_LLM_API_KEY"),
    model=os.getenv("RAGAS_LLM_MODEL"),
    temperature=0.1,
    max_retries=3,
    timeout=30
)

# 1.4 启用 LangChain 缓存（Redis），降低 LLM 调用次数
cache = RedisCache(
    redis_url=os.getenv("LANGCHAIN_REDIS_URL"),
    ttl=3600  # 缓存 1 小时
)
# 语义缓存（可选，针对相似问题复用结果）
# semantic_cache = RedisSemanticCache(redis_url=os.getenv("LANGCHAIN_REDIS_URL"), embedding=embeddings)

# -------------------------- 2. 构建 LCEL 标准化 RAG 链（LangChain 1.0 核心） --------------------------
# 提示词模板
prompt = ChatPromptTemplate.from_template("""
基于以下上下文回答用户问题，要求准确、简洁、符合业务规范：
上下文：{context}
用户问题：{question}
""")

# LCEL 链式调用（流式、可组合、可扩展）
rag_chain = (
    RunnableParallel({
        "context": retriever,
        "question": RunnablePassthrough()
    })
    | prompt
    | llm
    | StrOutputParser()
)

# 启用缓存（仅针对 LLM 调用）
rag_chain = rag_chain.with_config(cache=cache)

# -------------------------- 3. 核心 RAG 调用函数 --------------------------
def run_rag(question: str) -> tuple[str, list[str]]:
    """
    执行 RAG 流程，返回答案+检索上下文
    :param question: 用户问题
    :return: (answer, contexts)
    """
    # 执行 LCEL 链
    answer = rag_chain.invoke(question)
    
    # 单独获取检索上下文（用于 RAGAS 评估）
    contexts = [doc.page_content for doc in retriever.invoke(question)]
    
    return answer, contexts
