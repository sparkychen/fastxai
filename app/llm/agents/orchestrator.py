# -*- coding: utf-8 -*-

from typing import Dict, List, Any, Optional
from langgraph.graph import StateGraph, END
from langgraph.checkpoint import MemorySaver
from langchain_core.messages import HumanMessage, AIMessage
from langchain_openai import ChatOpenAI
import structlog

from src.config.settings import settings
from src.agents.base import BaseAgent
from src.agents.manager import AgentManager

logger = structlog.get_logger()

class AgentState(Dict[str, Any]):
    """State for agent orchestration"""
    messages: List[Dict[str, Any]]
    current_agent: Optional[str]
    next_agent: Optional[str]
    agent_results: Dict[str, Any]
    user_query: str
    final_answer: Optional[str]

class MultiAgentOrchestrator:
    """Orchestrates multiple agents using LangGraph"""
    
    def __init__(self):
        self.llm = ChatOpenAI(
            model="gpt-4-1106-preview",
            temperature=0.1,
            api_key=settings.OPENAI_API_KEY,
        )
        self.agent_manager = AgentManager()
        self.checkpointer = MemorySaver()
        self.graph = self._build_graph()
    
    def _build_graph(self) -> StateGraph:
        """Build the agent orchestration graph"""
        
        # Create state graph
        workflow = StateGraph(AgentState)
        
        # Add nodes
        workflow.add_node("router", self._route_query)
        workflow.add_node("research_agent", self._run_research_agent)
        workflow.add_node("coding_agent", self._run_coding_agent)
        workflow.add_node("analysis_agent", self._run_analysis_agent)
        workflow.add_node("synthesizer", self._synthesize_results)
        
        # Set entry point
        workflow.set_entry_point("router")
        
        # Define edges
        workflow.add_conditional_edges(
            "router",
            self._decide_next_agent,
            {
                "research": "research_agent",
                "coding": "coding_agent",
                "analysis": "analysis_agent",
            }
        )
        
        # Connect agent nodes to synthesizer
        workflow.add_edge("research_agent", "synthesizer")
        workflow.add_edge("coding_agent", "synthesizer")
        workflow.add_edge("analysis_agent", "synthesizer")
        
        # Set end point
        workflow.add_edge("synthesizer", END)
        
        # Compile with checkpointing
        return workflow.compile(checkpointer=self.checkpointer)
    
    def _route_query(self, state: AgentState) -> Dict[str, Any]:
        """Route query to appropriate agent"""
        logger.info("Routing query", query=state["user_query"])
        
        # Simple routing logic - can be enhanced with ML
        query = state["user_query"].lower()
        
        if any(word in query for word in ["research", "find", "search", "look up"]):
            return {"next_agent": "research"}
        elif any(word in query for word in ["code", "program", "develop", "script"]):
            return {"next_agent": "coding"}
        elif any(word in query for word in ["analyze", "analyze", "compare", "evaluate"]):
            return {"next_agent": "analysis"}
        else:
            return {"next_agent": "research"}  # Default
    
    def _decide_next_agent(self, state: AgentState) -> str:
        """Decide which agent to run next"""
        return state.get("next_agent", "research")
    
    def _run_research_agent(self, state: AgentState) -> Dict[str, Any]:
        """Run research agent"""
        logger.info("Running research agent")
        agent = self.agent_manager.get_agent("research")
        result = agent.run(state["user_query"])
        return {
            "agent_results": {**state.get("agent_results", {}), "research": result},
            "current_agent": "research",
        }
    
    def _run_coding_agent(self, state: AgentState) -> Dict[str, Any]:
        """Run coding agent"""
        logger.info("Running coding agent")
        agent = self.agent_manager.get_agent("coding")
        result = agent.run(state["user_query"])
        return {
            "agent_results": {**state.get("agent_results", {}), "coding": result},
            "current_agent": "coding",
        }
    
    def _run_analysis_agent(self, state: AgentState) -> Dict[str, Any]:
        """Run analysis agent"""
        logger.info("Running analysis agent")
        agent = self.agent_manager.get_agent("analysis")
        result = agent.run(state["user_query"])
        return {
            "agent_results": {**state.get("agent_results", {}), "analysis": result},
            "current_agent": "analysis",
        }
    
    def _synthesize_results(self, state: AgentState) -> Dict[str, Any]:
        """Synthesize results from all agents"""
        logger.info("Synthesizing results")
        
        # Get results from all agents
        results = state.get("agent_results", {})
        
        # Generate final answer using LLM
        prompt = f"""
        User Query: {state['user_query']}
        
        Agent Results:
        {results}
        
        Please provide a comprehensive, synthesized answer based on the agent results above.
        """
        
        response = self.llm.invoke([HumanMessage(content=prompt)])
        final_answer = response.content
        
        return {
            "final_answer": final_answer,
            "agent_results": results,
        }
    
    async def run(self, query: str, config: Dict[str, Any] = None) -> Dict[str, Any]:
        """Run the multi-agent system"""
        logger.info("Starting multi-agent orchestration", query=query)
        
        initial_state = AgentState(
            messages=[],
            current_agent=None,
            next_agent=None,
            agent_results={},
            user_query=query,
            final_answer=None,
        )
        
        # Run the graph
        final_state = await self.graph.ainvoke(
            initial_state,
            config=config or {"configurable": {"thread_id": "user_thread"}}
        )
        
        logger.info("Multi-agent orchestration completed")
        return {
            "answer": final_state["final_answer"],
            "agent_results": final_state["agent_results"],
            "agents_used": list(final_state["agent_results"].keys()),
        }