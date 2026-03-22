"""
log_analyzer_agent.py
---------------------
Central orchestrator that ties together:
  1. SplunkIngestor  – fetches new log events
  2. KnowledgeBase   – retrieves similar past cases and stores new ones
  3. LLMInterface    – generates root-cause analysis via MiniMax
  4. AlertManager    – fires email / webhook alerts when warranted

The agent is designed to run in a continuous loop (schedule-based) or
to process a single batch of logs on demand.
"""

import logging
from typing import Any, Dict, List, Optional

from alert_manager import AlertManager
from knowledge_base import KnowledgeBase
from llm_interface import LLMInterface
from splunk_ingestor import SplunkIngestor

logger = logging.getLogger(__name__)


class LogAnalyzerAgent:
    """
    Agentic log analysis pipeline.

    Flow per log event
    ──────────────────
    fetch_logs()
        └─► for each event:
                ├─► find_similar_cases()          (knowledge base)
                ├─► analyse(event, similar_cases) (LLM)
                ├─► save_case()                   (knowledge base)
                └─► if should_alert → fire()      (alert manager)
    """

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self._ingestor = SplunkIngestor(cfg["splunk"])
        self._kb = KnowledgeBase(cfg["knowledge_base"])
        self._llm = LLMInterface(cfg["llm"])
        self._alerts = AlertManager(cfg["alerts"])
        self._similar_cases_limit: int = cfg["llm"].get("similar_cases_limit", 3)

    # ------------------------------------------------------------------
    # Main entry point – call this on each scheduled tick
    # ------------------------------------------------------------------

    def run_cycle(self) -> List[Dict[str, Any]]:
        """
        Fetch, analyse, and (if needed) alert on the latest Splunk logs.
        Returns a list of result dicts for display / testing.
        """
        logger.info("Starting analysis cycle – fetching logs from Splunk…")
        events = self._ingestor.fetch_logs()
        logger.info("Fetched %d log event(s).", len(events))

        results = []
        for event in events:
            result = self._process_event(event)
            results.append(result)

        logger.info(
            "Cycle complete. Processed %d event(s), alerts fired: %d.",
            len(results),
            sum(1 for r in results if r.get("alert_fired")),
        )
        return results

    def process_single(self, log_event: Dict[str, Any]) -> Dict[str, Any]:
        """Analyse a single log event (useful for ad-hoc / testing)."""
        return self._process_event(log_event)

    # ------------------------------------------------------------------
    # Per-event pipeline
    # ------------------------------------------------------------------

    def _process_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        # 1. Retrieve similar past cases for few-shot context
        similar = self._kb.find_similar_cases(event, limit=self._similar_cases_limit)
        logger.debug(
            "Found %d similar past case(s) for event from source=%s",
            len(similar),
            event.get("source", "?"),
        )

        # 2. Ask the LLM for root-cause analysis
        analysis = self._llm.analyse(event, similar)
        logger.info(
            "[%s] %s (confidence=%.0f%%)",
            analysis.get("severity", "?"),
            analysis.get("summary", ""),
            analysis.get("confidence", 0) * 100,
        )

        # 3. Persist the case
        case_id = self._kb.save_case(event, analysis)

        # 4. Fire alerts if the event warrants it
        alert_results: Dict[str, str] = {}
        alert_fired = self._alerts.should_alert(event, analysis)
        if alert_fired:
            logger.warning(
                "⚠ Alert condition met for case_id=%d – dispatching alerts…", case_id
            )
            alert_results = self._alerts.fire(event, analysis, case_id)
            for channel, status in alert_results.items():
                self._kb.log_alert(case_id, channel, status)

        return {
            "case_id": case_id,
            "event": event,
            "analysis": analysis,
            "similar_cases": similar,
            "alert_fired": alert_fired,
            "alert_results": alert_results,
        }

    # ------------------------------------------------------------------
    # Feedback loop
    # ------------------------------------------------------------------

    def submit_feedback(
        self,
        case_id: int,
        feedback: str,
        notes: str = "",
    ) -> None:
        """
        Record user feedback for a case.
        feedback: 'correct' | 'incorrect' | 'partial'
        This enriches the knowledge base so future similar events benefit
        from the corrected analysis.
        """
        self._kb.record_feedback(case_id, feedback, notes)
        logger.info(
            "Feedback '%s' recorded for case_id=%d. Knowledge base updated.", feedback, case_id
        )

    # ------------------------------------------------------------------
    # Convenience accessors
    # ------------------------------------------------------------------

    def get_case(self, case_id: int) -> Optional[Dict[str, Any]]:
        return self._kb.get_case(case_id)

    def list_recent_cases(self, limit: int = 20) -> List[Dict[str, Any]]:
        return self._kb.list_recent_cases(limit)

    def close(self) -> None:
        self._kb.close()
