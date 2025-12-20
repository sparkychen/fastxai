# -*- coding: utf-8 -*-

from ragas import evaluate
from ragas.metrics import faithfulness, answer_relevancy, context_precision
from langchain_openai import ChatOpenAI, OpenAIEmbeddings
from datasets import Dataset
import asyncio

"""部署独立的评估 Worker，从消息队列消费任务并进行批量评估"""

class RagasEvaluationWorker:
    def __init__(self, batch_size: int = 50):
        self.batch_size = batch_size
        # 使用成本更低的模型进行评估[2](@ref)
        self.evaluation_llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0)
        self.embeddings = OpenAIEmbeddings()

    async def process_batch(self, batch_data: list) -> dict:
        """批量处理评估数据，显著提升效率"""
        if not batch_data:
            return {}
        
        # 准备 Ragas 评估数据集
        dataset_dict = {
            "question": [item["question"] for item in batch_data],
            "answer": [item["answer"] for item in batch_data],
            "contexts": [item["contexts"] for item in batch_data]
        }
        rag_dataset = Dataset.from_dict(dataset_dict)
        
        # 执行批量评估[1,5](@ref)
        result = evaluate(
            dataset=rag_dataset,
            metrics=[faithfulness, answer_relevancy, context_precision],
            llm=self.evaluation_llm,
            embeddings=self.embeddings
        )
        
        # 推送到监控系统
        await self._push_metrics_to_tsdb(result, batch_data)
        return result

    async def _push_metrics_to_tsdb(self, results, source_data):
        """将评估结果推送到监控系统"""
        for i, single_result in enumerate(results):
            # 记录核心指标到 Prometheus[2](@ref)
            faithfulness_metric.labels(
                user_segment=source_data[i].get("user_segment", "default")
            ).set(single_result["faithfulness"])
            
            answer_relevancy_metric.labels(
                user_segment=source_data[i].get("user_segment", "default")
            ).set(single_result["answer_relevancy"])