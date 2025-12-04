# -*- coding: utf-8 -*-

from typing import List, Optional, Dict, Any
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
import numpy as np
import structlog

from app.config.settings import settings

logger = structlog.get_logger()

class VectorService:
    """Service for vector database operations"""
    
    def __init__(self):
        self.client = None
        self.collection_name = "documents"
    
    async def initialize(self):
        """Initialize vector database connection"""
        try:
            if settings.VECTOR_STORE_TYPE == "qdrant":
                self.client = QdrantClient(
                    url=settings.QDRANT_URL,
                    api_key=settings.QDRANT_API_KEY,
                    timeout=30,
                )
                
                # Create collection if not exists
                collections = self.client.get_collections().collections
                collection_names = [c.name for c in collections]
                
                if self.collection_name not in collection_names:
                    self.client.create_collection(
                        collection_name=self.collection_name,
                        vectors_config=VectorParams(
                            size=1536,  # OpenAI embedding dimension
                            distance=Distance.COSINE,
                        ),
                    )
                    logger.info(f"Created collection: {self.collection_name}")
            
            elif settings.VECTOR_STORE_TYPE == "milvus":
                from pymilvus import connections, utility, Collection, FieldSchema, CollectionSchema, DataType
                
                connections.connect(
                    alias="default",
                    host=settings.MILVUS_HOST,
                    port=settings.MILVUS_PORT,
                )
                
                if not utility.has_collection(self.collection_name):
                    fields = [
                        FieldSchema(name="id", dtype=DataType.INT64, is_primary=True, auto_id=True),
                        FieldSchema(name="text", dtype=DataType.VARCHAR, max_length=65535),
                        FieldSchema(name="embedding", dtype=DataType.FLOAT_VECTOR, dim=1536),
                        FieldSchema(name="metadata", dtype=DataType.JSON),
                    ]
                    schema = CollectionSchema(fields, description="Document embeddings")
                    self.collection = Collection(self.collection_name, schema)
                    
                    # Create index
                    index_params = {
                        "metric_type": "IP",
                        "index_type": "IVF_FLAT",
                        "params": {"nlist": 128},
                    }
                    self.collection.create_index("embedding", index_params)
            
            logger.info("Vector service initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize vector service: {str(e)}")
            raise
    
    async def store_embeddings(
        self,
        texts: List[str],
        embeddings: List[List[float]],
        metadatas: Optional[List[Dict[str, Any]]] = None,
    ) -> List[str]:
        """Store text embeddings in vector database"""
        try:
            if settings.VECTOR_STORE_TYPE == "qdrant":
                points = []
                for idx, (text, embedding) in enumerate(zip(texts, embeddings)):
                    point = PointStruct(
                        id=idx,
                        vector=embedding,
                        payload={
                            "text": text,
                            "metadata": metadatas[idx] if metadatas else {},
                        }
                    )
                    points.append(point)
                
                operation_info = self.client.upsert(
                    collection_name=self.collection_name,
                    points=points,
                )
                
                return [str(i) for i in range(len(texts))]
            
            elif settings.VECTOR_STORE_TYPE == "milvus":
                entities = []
                for text, embedding, metadata in zip(texts, embeddings, metadatas or [{}]):
                    entities.append([text, embedding, metadata])
                
                self.collection.insert(entities)
                self.collection.flush()
                
                return [str(i) for i in range(len(texts))]
        
        except Exception as e:
            logger.error(f"Failed to store embeddings: {str(e)}")
            raise
    
    async def search_similar(
        self,
        query_embedding: List[float],
        limit: int = 10,
        score_threshold: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Search for similar embeddings"""
        try:
            if settings.VECTOR_STORE_TYPE == "qdrant":
                search_result = self.client.search(
                    collection_name=self.collection_name,
                    query_vector=query_embedding,
                    limit=limit,
                    score_threshold=score_threshold,
                )
                
                results = []
                for hit in search_result:
                    results.append({
                        "id": str(hit.id),
                        "score": hit.score,
                        "text": hit.payload.get("text", ""),
                        "metadata": hit.payload.get("metadata", {}),
                    })
                
                return results
            
            elif settings.VECTOR_STORE_TYPE == "milvus":
                self.collection.load()
                
                search_params = {
                    "metric_type": "IP",
                    "params": {"nprobe": 10},
                }
                
                search_result = self.collection.search(
                    data=[query_embedding],
                    anns_field="embedding",
                    param=search_params,
                    limit=limit,
                    output_fields=["text", "metadata"],
                )
                
                results = []
                for hits in search_result:
                    for hit in hits:
                        results.append({
                            "id": str(hit.id),
                            "score": hit.score,
                            "text": hit.entity.get("text", ""),
                            "metadata": hit.entity.get("metadata", {}),
                        })
                
                return results
        
        except Exception as e:
            logger.error(f"Failed to search embeddings: {str(e)}")
            raise
    
    async def delete_embeddings(self, ids: List[str]) -> bool:
        """Delete embeddings by IDs"""
        try:
            if settings.VECTOR_STORE_TYPE == "qdrant":
                self.client.delete(
                    collection_name=self.collection_name,
                    points_selector=ids,
                )
            elif settings.VECTOR_STORE_TYPE == "milvus":
                expr = f"id in [{','.join(ids)}]"
                self.collection.delete(expr)
            
            return True
        
        except Exception as e:
            logger.error(f"Failed to delete embeddings: {str(e)}")
            return False