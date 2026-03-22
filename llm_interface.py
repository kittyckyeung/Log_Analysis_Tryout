"""
llm_interface.py
----------------
Wrapper around the MiniMax LLM API.
MiniMax exposes an OpenAI-compatible Chat Completions endpoint, so we use
the official `openai` SDK pointed at MiniMax's base URL.

Expected response JSON (parsed from the model reply):
{
    "severity":    "ERROR | WARNING | INFO | ...",
    "summary":     "One-line description of the problem",
    "root_cause":  "Detailed root-cause explanation",
    "solution":    "Step-by-step remediation advice",
    "related_components": ["service-a", "db-x"],
    "confidence":  0.85
}
"""

import json
import logging
from typing import Any, Dict, List, Optional

from openai import OpenAI

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# System prompt – defines the agent's persona and output contract
# --------------------------------------------------------------------------
SYSTEM_PROMPT = """\
You are an expert SRE (Site Reliability Engineer) and security analyst specialising \
in log analysis and incident response. Your job is to analyse application log entries \
forwarded from Splunk, identify problems, determine root causes, and propose concrete \
remediation steps.

You MUST reply with a single valid JSON object (no markdown fences, no extra text) \
matching this exact schema:
{
  "severity":            "<CRITICAL|ERROR|WARNING|INFO>",
  "summary":             "<one-line problem description>",
  "root_cause":          "<detailed root-cause analysis>",
  "solution":            "<numbered step-by-step remediation>",
  "related_components":  ["<component1>", "..."],
  "confidence":          <float 0.0–1.0>
}

Rules:
- Be specific and actionable. Avoid vague statements.
- If similar past cases are provided, use them to inform your analysis.
- If you cannot determine a root cause, say so clearly in root_cause and \
  set confidence to a low value.
- Never invent facts not supported by the log data.
"""


class LLMInterface:
    """Communicates with the MiniMax LLM to perform log analysis."""

    def __init__(self, cfg: Dict[str, Any]) -> None:
        self._model: str = cfg.get("model", "abab6.5s-chat")
        self._max_tokens: int = cfg.get("max_tokens", 2048)
        self._temperature: float = cfg.get("temperature", 0.2)
        self._group_id: str = cfg.get("group_id", "")

        # MiniMax OpenAI-compatible endpoint
        base_url = cfg.get("base_url", "https://api.minimax.chat/v1")
        api_key = cfg["api_key"]

        # MiniMax requires GroupId in the URL for some endpoints; we append it
        # only when a group_id is configured.
        if self._group_id:
            base_url = f"{base_url.rstrip('/')}?GroupId={self._group_id}"

        self._client = OpenAI(api_key=api_key, base_url=base_url)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def analyse(
        self,
        log_event: Dict[str, Any],
        similar_cases: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Send a log event (plus optional similar past cases) to the LLM and
        return structured analysis as a dict.
        """
        messages = self._build_messages(log_event, similar_cases or [])
        raw_reply = self._call_api(messages)
        return self._parse_reply(raw_reply)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_messages(
        self,
        log_event: Dict[str, Any],
        similar_cases: List[Dict[str, Any]],
    ) -> List[Dict[str, str]]:
        """Construct the chat message list for the API call."""
        messages: List[Dict[str, str]] = [{"role": "system", "content": SYSTEM_PROMPT}]

        # Inject similar past cases as context (few-shot learning)
        if similar_cases:
            cases_text = "\n\n".join(
                f"--- Past Case #{i + 1} (similarity: {c.get('similarity', 0):.0%}) ---\n"
                f"Log snippet: {c.get('log_snippet', '')}\n"
                f"Root cause: {c.get('root_cause', '')}\n"
                f"Solution: {c.get('solution', '')}\n"
                f"User feedback: {c.get('user_feedback', 'N/A')}"
                for i, c in enumerate(similar_cases)
            )
            messages.append(
                {
                    "role": "user",
                    "content": (
                        "Here are similar past cases from our knowledge base. "
                        "Use them to inform your analysis:\n\n" + cases_text
                    ),
                }
            )
            messages.append(
                {"role": "assistant", "content": "Understood. I will use these past cases."}
            )

        # The actual log event to analyse
        log_text = json.dumps(log_event, indent=2, default=str)
        messages.append(
            {
                "role": "user",
                "content": (
                    "Please analyse the following Splunk log event and return your "
                    "structured JSON analysis:\n\n" + log_text
                ),
            }
        )
        return messages

    def _call_api(self, messages: List[Dict[str, str]]) -> str:
        """Call the MiniMax Chat Completions API and return the raw text reply."""
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                messages=messages,  # type: ignore[arg-type]
                max_tokens=self._max_tokens,
                temperature=self._temperature,
            )
            return response.choices[0].message.content or ""
        except Exception as exc:
            logger.error("LLM API call failed: %s", exc)
            return json.dumps(
                {
                    "severity": "UNKNOWN",
                    "summary": "LLM analysis unavailable",
                    "root_cause": f"API error: {exc}",
                    "solution": "Check LLM API connectivity and credentials.",
                    "related_components": [],
                    "confidence": 0.0,
                }
            )

    @staticmethod
    def _parse_reply(raw: str) -> Dict[str, Any]:
        """Parse the LLM's JSON reply, falling back gracefully on malformed output."""
        # Strip accidental markdown fences the model may add despite instructions
        cleaned = raw.strip()
        if cleaned.startswith("```"):
            lines = cleaned.splitlines()
            cleaned = "\n".join(
                ln for ln in lines if not ln.strip().startswith("```")
            ).strip()

        try:
            result = json.loads(cleaned)
            # Normalise confidence to float
            result["confidence"] = float(result.get("confidence", 0.5))
            return result
        except (json.JSONDecodeError, ValueError):
            logger.warning("LLM returned non-JSON response; wrapping raw text.")
            return {
                "severity": "UNKNOWN",
                "summary": "Could not parse LLM response",
                "root_cause": raw,
                "solution": "Review raw LLM output above.",
                "related_components": [],
                "confidence": 0.0,
            }
