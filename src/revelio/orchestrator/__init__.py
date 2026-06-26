"""Multi-agent orchestration module."""

from revelio.orchestrator.context import ContextPacket, ContextPacketBuilder, render_context_packet
from revelio.orchestrator.file_hypothesis import FileHypothesisRunner
from revelio.orchestrator.hypothesis import HypothesisOrchestrator
from revelio.orchestrator.runner import MultiAgentOrchestrator
from revelio.orchestrator.scan_filter import ScanFilterOrchestrator
from revelio.orchestrator.specs import default_agent_specs
from revelio.orchestrator.types import AgentSpec, OrchestratorResult

__all__ = [
    "ContextPacket",
    "ContextPacketBuilder",
    "render_context_packet",
    "HypothesisOrchestrator",
    "MultiAgentOrchestrator",
    "ScanFilterOrchestrator",
    "AgentSpec",
    "OrchestratorResult",
    "default_agent_specs",
]
