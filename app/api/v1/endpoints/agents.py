# -*- coding: utf-8 -*-

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
import structlog

from src.api.dependencies import get_current_user
from src.config.database import get_db
from src.domain.models.user import User
from src.services.agent_service import AgentService
from src.domain.schemas.agent import (
    AgentCreate,
    AgentResponse,
    AgentUpdate,
    AgentQuery,
    AgentExecutionResponse,
)

router = APIRouter(prefix="/agents", tags=["agents"])
logger = structlog.get_logger()

@router.post("/", response_model=AgentResponse)
async def create_agent(
    agent_data: AgentCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Create a new agent"""
    try:
        agent_service = AgentService(db)
        agent = await agent_service.create_agent(agent_data, current_user.id)
        return AgentResponse.from_orm(agent)
    except Exception as e:
        logger.error(f"Failed to create agent: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

@router.get("/", response_model=List[AgentResponse])
async def list_agents(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all agents for current user"""
    agent_service = AgentService(db)
    agents = await agent_service.get_user_agents(current_user.id, skip, limit)
    return [AgentResponse.from_orm(agent) for agent in agents]

@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get agent by ID"""
    agent_service = AgentService(db)
    agent = await agent_service.get_agent_by_id(agent_id, current_user.id)
    
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )
    
    return AgentResponse.from_orm(agent)

@router.put("/{agent_id}", response_model=AgentResponse)
async def update_agent(
    agent_id: str,
    agent_data: AgentUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Update agent"""
    agent_service = AgentService(db)
    agent = await agent_service.update_agent(agent_id, agent_data, current_user.id)
    
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )
    
    return AgentResponse.from_orm(agent)

@router.delete("/{agent_id}")
async def delete_agent(
    agent_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Delete agent"""
    agent_service = AgentService(db)
    success = await agent_service.delete_agent(agent_id, current_user.id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )
    
    return {"message": "Agent deleted successfully"}

@router.post("/{agent_id}/execute", response_model=AgentExecutionResponse)
async def execute_agent(
    agent_id: str,
    query: AgentQuery,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Execute an agent"""
    agent_service = AgentService(db)
    
    # Check if agent exists and belongs to user
    agent = await agent_service.get_agent_by_id(agent_id, current_user.id)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Agent not found",
        )
    
    # Execute agent in background
    execution_id = await agent_service.execute_agent(
        agent_id=agent_id,
        query=query.query,
        parameters=query.parameters or {},
        user_id=current_user.id,
    )
    
    # Add to background tasks if it's a long-running operation
    if query.async_execution:
        background_tasks.add_task(
            agent_service.process_agent_execution,
            execution_id,
        )
        return AgentExecutionResponse(
            execution_id=execution_id,
            status="processing",
            message="Agent execution started in background",
        )
    else:
        # Execute synchronously
        result = await agent_service.process_agent_execution(execution_id)
        return AgentExecutionResponse(
            execution_id=execution_id,
            status="completed",
            result=result,
        )

@router.post("/multi-agent/execute")
async def execute_multi_agent(
    query: AgentQuery,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Execute multi-agent orchestration"""
    try:
        from src.agents.orchestrator import MultiAgentOrchestrator
        
        orchestrator = MultiAgentOrchestrator()
        result = await orchestrator.run(query.query)
        
        # Store execution history
        agent_service = AgentService(db)
        await agent_service.log_multi_agent_execution(
            user_id=current_user.id,
            query=query.query,
            result=result,
        )
        
        return result
    
    except Exception as e:
        logger.error(f"Multi-agent execution failed: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Multi-agent execution failed: {str(e)}",
        )