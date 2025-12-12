# -*- coding: utf-8 -*-

# pip install transformers torch sentence-transformers

from sentence_transformers import SentenceTransformer
from transformers import AutoModelForSequenceClassification, AutoTokenizer
import torch
import numpy as np

# 1. 配置Embedding模型（智谱GLM-4.5 Embedding）
embedding_model = SentenceTransformer(
    "ZhipuAI/GLM-4.5-Embedding",
    device="cuda"
)
embedding_model.max_seq_length = 512

# 2. 配置Rerank模型（智谱GLM-4.6 Rerank）
rerank_model = AutoModelForSequenceClassification.from_pretrained(
    "ZhipuAI/GLM-4.6-Rerank",
    num_labels=1,
    torch_dtype=torch.float16
).to("cuda")
rerank_tokenizer = AutoTokenizer.from_pretrained("ZhipuAI/GLM-4.6-Rerank")
rerank_tokenizer.model_max_length = 512

# 3. 模拟向量数据库检索（实际使用FAISS/Pinecone）
def vector_search(query, top_k=5):
    """模拟向量检索（实际使用FAISS/Pinecone）"""
    embedding = embedding_model.encode([query])[0]
    
    # 模拟数据库返回结果（实际中从数据库获取）
    mock_results = [
        {"text": "免赔额是保险合同中规定的损失赔偿的最低限额", "score": 0.85},
        {"text": "免赔额是保险理赔时需自行承担的部分", "score": 0.82},
        {"text": "免赔额影响保险费用计算", "score": 0.78},
        {"text": "免赔额与保险类型相关", "score": 0.75},
        {"text": "免赔额条款在合同第5条", "score": 0.72}
    ]
    
    # 按原始分数排序
    return sorted(mock_results, key=lambda x: x["score"], reverse=True)[:top_k]

# 4. 企业级Rerank函数
def rerank_results(query, results):
    """使用GLM-4.6 Rerank重排序"""
    inputs = [(query, r["text"]) for r in results]
    
    with torch.no_grad():
        encoded = rerank_tokenizer(
            inputs,
            padding=True,
            truncation=True,
            return_tensors="pt",
            max_length=512
        ).to("cuda")
        
        scores = rerank_model(**encoded).logits.squeeze().cpu().numpy()
    
    ranked = sorted(zip(results, scores), key=lambda x: x[1], reverse=True)
    return [item[0] for item in ranked]

# 5. 企业级RAG流程
def rag_pipeline(query):
    """企业级RAG全流程"""
    # 步骤1: 向量检索
    search_results = vector_search(query, top_k=5)
    
    # 步骤2: Rerank重排序
    reranked = rerank_results(query, search_results)
    
    # 步骤3: 传递给GLM-4.6生成响应
    context = "\n".join([r["text"] for r in reranked])
    prompt = f"基于以下知识:\n{context}\n问题: {query}\n回答:"
    
    # 实际使用GLM-4.6生成（此处简化）
    response = f"根据知识图谱，{query} 的关键信息是：{reranked[0]['text']}"
    
    return {
        "query": query,
        "retrieved": reranked,
        "response": response
    }

# 6. 执行RAG流程
if __name__ == "__main__":
    result = rag_pipeline("汽车保险中的免赔额规定是什么？")
    print("最终响应:", result["response"])