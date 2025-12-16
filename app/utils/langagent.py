# -*- coding: utf-8 -*-

import os
import asyncio
from langchain_openai import ChatOpenAI
from langchain.agents import create_agent
from graphiti_core.errors import NodeNotFoundError, EdgeNotFoundError, EntityTypeValidationError
from graphiti_core import Graphiti
from neo4j import GraphDatabase, exceptions
from graphiti_core.llm_client.config import LLMConfig
from graphiti_core.llm_client.openai_generic_client import OpenAIGenericClient
from graphiti_core.embedder.openai import OpenAIEmbedder, OpenAIEmbedderConfig
from graphiti_core.cross_encoder.openai_reranker_client import OpenAIRerankerClient
from graphiti_core.llm_client.openai_client import OpenAIClient
from graphiti_core.search.search_config import SearchConfig
from graphiti_core.driver.neo4j_driver import Neo4jDriver
from openai import OpenAI
from openai._exceptions import APIConnectionError as OpenAIConnectionError
from langchain_core.prompts import ChatPromptTemplate
import traceback
import logging
from langchain_core.tools import tool 

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "neo4jPass#123")
QWEN_API_BASE = os.getenv("QWEN_API_BASE", "http://localhost:11434/v1")
QWEN_API_KEY = os.getenv("QWEN_API_KEY", "EMPTY")  # 本地模型可能不需要API密钥，填任意值
LLM_MODEL = os.getenv("LLM_MODEL", "qwen3:8b")
EMBEDDING_MODEL = os.getenv("EMBEDDING_MODEL", "qwen3-embedding:0.6b")
logging.getLogger('neo4j.notifications').setLevel(logging.ERROR)
# # 完全静音 Neo4j 日志（谨慎使用！）
# logging.getLogger('neo4j').setLevel(logging.CRITICAL)
logging.getLogger("httpx").setLevel(logging.ERROR)


llm_config = LLMConfig(
    api_key=QWEN_API_KEY,
    model=LLM_MODEL,
    small_model=LLM_MODEL,
    base_url=QWEN_API_BASE,
    max_tokens=8192 * 2,
    temperature=0.75
)
llm_client = OpenAIGenericClient(config=llm_config)
embedder_config = OpenAIEmbedderConfig(api_key=QWEN_API_KEY, base_url=QWEN_API_BASE, embedding_model=EMBEDDING_MODEL, embedding_dim=1024)
embedder = OpenAIEmbedder(config=embedder_config)
cross_encoder = OpenAIRerankerClient(config=llm_config, client=llm_client)
neo4j_driver = Neo4jDriver(uri=NEO4J_URI, user=NEO4J_USER, password=NEO4J_PASSWORD, database="neo4j")

graphiti = Graphiti(
    graph_driver=neo4j_driver,
    llm_client=llm_client,
    embedder=embedder,
    cross_encoder=cross_encoder,
    max_coroutines=20
)
ollama_model = ChatOpenAI(
    base_url="http://localhost:11434/v1",  # 本地Ollama服务地址
    api_key="ollama",                     # 与你的配置保持一致
    model="qwen3:8b",                     # 这是关键！必须在ChatOpenAI里指定模型名
    timeout=180,                          # 超时设置
    # 其他可选参数，如 temperature 等，也可在这里设置
    temperature=0.7,
    max_tokens=5120,
)
client = OpenAI(
        api_key="ollama",
        base_url="http://localhost:11434/v1",
        timeout=180,
    )
response = client.chat.completions.create(
                model="qwen3:8b",
                messages=[
                    {"role": "user", "content": "Hello, 请将一个小笑话."}
                ],
                temperature=0.7,
                max_tokens=2048,
                timeout=180,
                stream=False,
            )
resp = response.choices[0].message.content
print(resp)

@tool
def query_neo4j(query: str) -> str: # langchain-1.0的tool须是同步的
    """ query neo4j database and return results based on 'query' content.\n
        查询Neo4j数据库，返回检索到的结果（只返回事实，不生成回答）
    """
    # 在同步函数中创建一个新的事件循环来运行异步代码
    async def _async_search():
        try:
            related_nodes = await graphiti.search( #graphiti.search是异步方法
                    query=query,
                    num_results=10
                )
            facts = [result.fact for result in related_nodes]
            if len(facts) == 0:
                return "Sorry，没有查到相关信息。"        
            return "\n".join(facts)
        except OpenAIConnectionError as e:
            traceback.print_exc()
            raise
        except NodeNotFoundError as e:
            print("未找到节点")
            raise e
        except EdgeNotFoundError as e:
            print("为找到关系")
            raise e
    return asyncio.run(_async_search())
# prompt=ChatPromptTemplate.from_messages([
#         ("system", "你是一个AI助手，基于检索到的知识回答问题。请使用中文回答，保持口语化。"),
#         ("human", "{input}")
#     ])
agent = create_agent(
    model=ollama_model,
    tools=[query_neo4j],
    system_prompt="你是一个AI助手，必须且只能使用从知识图谱检索到的知识回答问题。请使用中文回答，保持口语化。",
    # system_prompt="你是一个AI助手，基于使用知识图谱检索到的知识内容回答问题，不要胡编乱造没有检索到的内容。请使用中文回答，保持口语化。",
)
resp = agent.invoke(
    {"messages": [{"role": "user", "content": "预算6000元的智能手机，请推荐一个这价位手机性能特点，给出有用的选购建议"}]},
    stream_mode="values",
)
print(resp)
# 获取真正的最终回答（最后一个AIMessage的content）
final_answer = resp["messages"][-1].content
print(f"\n*** {final_answer}")