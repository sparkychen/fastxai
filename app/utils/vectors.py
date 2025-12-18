# -*- coding: utf-8 -*-

import os
from pathlib import Path
from langchain_openai import OpenAIEmbeddings
from langchain_community.embeddings import OllamaEmbeddings
from langchain_milvus import Milvus
import asyncio  # 用于初始化异步事件循环（可选，彻底消除异步报错）

# 解决Windows下asyncio事件循环问题（可选但推荐）
def fix_async_loop():
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    return loop
# 初始化事件循环（彻底消除AsyncMilvusClient报错）
# fix_async_loop()

PROJECT_ROOT = Path(__file__).parent.parent.parent
DB_DIR = os.path.join(PROJECT_ROOT, "vector_storage")
DB_FILE_PATH = os.path.join(DB_DIR, "milvus_example.db")
print(DB_FILE_PATH)
# 3. 确保目录存在
os.makedirs(DB_DIR, exist_ok=True)

# embeddings = OpenAIEmbeddings(
#     model="qwen3-embedding:4b",
#     base_url="http://localhost:11434/v1",
#     api_key="ollama",
#     dimensions=1024)
embeddings = OllamaEmbeddings(
    model="qwen3-embedding:4b",
    base_url="http://localhost:11434",
)
# print(embeddings.embed_query("test"))

async def main():
    vector_store = Milvus(
        embedding_function=embeddings,
        connection_args={
            "uri": "http://localhost:19530",
            "user": "",  # 无认证时留空（默认无需账号密码）
            "password": "",
            "secure": False,  # 非HTTPS连接，设为False
        },
        collection_name="test_collection",
        index_params={"index_type": "FLAT", "metric_type": "L2"},
        drop_old=False,
        auto_id=False,
        timeout=10,
    )
    print(vector_store.client.list_collections())

if __name__ == "__main__":
    asyncio.run(main()) 
