# -*- coding: utf-8 -*-

import os
from pathlib import Path
from langchain_openai import OpenAIEmbeddings
from langchain_community.embeddings import OllamaEmbeddings
from langchain_milvus import Milvus

PROJECT_ROOT = Path(__file__).parent.parent
DB_DIR = os.path.join(PROJECT_ROOT, "vector_storage")
DB_FILE_PATH = os.path.join(DB_DIR, "milvus_example.db")
print(DB_FILE_PATH)
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



vector_store = Milvus(
    embedding_function=embeddings,
    connection_args={"uri": DB_FILE_PATH},
    index_params={"index_type": "FLAT", "metric_type": "L2"},
)

