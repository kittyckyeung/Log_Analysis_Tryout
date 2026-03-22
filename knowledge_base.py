"""
knowledge_base.py
-----------------
SQLite-backed store for analysed log cases and user feedback.
Supports:
  - Saving a new case (log snippet + LLM analysis)
  - Recording user feedback on a case (correct / incorrect / partial)
  - Retrieving similar past cases via TF-IDF cosine similarity
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity

logger = logging.getLogger(__name__)

# --------------------------------------------------------------------------
# DDL
# --------------------------------------------------------------------------
DDL = """
CREATE TABLE IF NOT EXISTS cases (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at      TEXT    NOT NULL,
    log_snippet     TEXT    NOT NULL,   -- JSON-serialised log event
    log_level       TEXT    NOT NULL,
    log_source      TEXT    NOT NULL,
    severity        TEXT,
    summary         TEXT,
    root_cause      TEXT,
    solution        TEXT,
    related_comps   TEXT,               -- JSON list
    confidence      REAL,
    user_feedback   TEXT,               -- 'correct' | 'incorrect' | 'partial' | NULL
    feedback_notes  TEXT,
    feedback_at     TEXT
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id     INTEGER REFERENCES cases(id),
    fired_at    TEXT    NOT NULL,
    channel     TEXT    NOT NULL,       -- 'email' | 'webhook'
    status      TEXT    NOT NULL,       -- 'sent' | 'failed'
    details     TEXT
);
"""


class KnowledgeBase:
    """Persistent store for log analysis cases and feedback."""

    def __init__(self, cfg: Dict[str, Any]) -> None:
        db_path: str = cfg.get("db_path", "knowledge_base.db")
        self._threshold: float = float(cfg.get("similarity_threshold", 0.30))
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(DDL)
        self._conn.commit()
        logger.info("Knowledge base initialised at %s", db_path)

    # ------------------------------------------------------------------
    # Case management
    # ------------------------------------------------------------------

    def save_case(
        self,
        log_event: Dict[str, Any],
        analysis: Dict[str, Any],
    ) -> int:
        """Persist a new case and return its auto-assigned ID."""
        now = datetime.now(timezone.utc).isoformat()
        cur = self._conn.execute(
            """
            INSERT INTO cases
                (created_at, log_snippet, log_level, log_source,
                 severity, summary, root_cause, solution,
                 related_comps, confidence)
            VALUES (?,?,?,?,?,?,?,?,?,?)
            """,
            (
                now,
                json.dumps(log_event, default=str),
                log_event.get("level", "UNKNOWN"),
                log_event.get("source", "unknown"),
                analysis.get("severity"),
                analysis.get("summary"),
                analysis.get("root_cause"),
                analysis.get("solution"),
                json.dumps(analysis.get("related_components", [])),
                analysis.get("confidence", 0.0),
            ),
        )
        self._conn.commit()
        case_id = cur.lastrowid
        logger.debug("Saved case id=%d", case_id)
        return case_id

    def record_feedback(
        self,
        case_id: int,
        feedback: str,
        notes: str = "",
    ) -> None:
        """
        Update a case with user feedback.
        feedback: 'correct' | 'incorrect' | 'partial'
        """
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            """
            UPDATE cases
               SET user_feedback = ?, feedback_notes = ?, feedback_at = ?
             WHERE id = ?
            """,
            (feedback, notes, now, case_id),
        )
        self._conn.commit()
        logger.info("Feedback recorded for case id=%d: %s", case_id, feedback)

    def get_case(self, case_id: int) -> Optional[Dict[str, Any]]:
        """Retrieve a single case by ID."""
        row = self._conn.execute(
            "SELECT * FROM cases WHERE id = ?", (case_id,)
        ).fetchone()
        return dict(row) if row else None

    def list_recent_cases(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Return the most recent cases (newest first)."""
        rows = self._conn.execute(
            "SELECT * FROM cases ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Similarity search (TF-IDF)
    # ------------------------------------------------------------------

    def find_similar_cases(
        self,
        log_event: Dict[str, Any],
        limit: int = 3,
    ) -> List[Dict[str, Any]]:
        """
        Return up to `limit` past cases whose log snippets are most similar
        to the current event, using TF-IDF cosine similarity.
        Only cases with user feedback are used so the model learns from
        verified knowledge.
        """
        rows = self._conn.execute(
            """
            SELECT id, log_snippet, root_cause, solution, user_feedback, confidence
              FROM cases
             WHERE user_feedback IS NOT NULL
             ORDER BY id DESC
             LIMIT 500
            """
        ).fetchall()

        if not rows:
            return []

        corpus = [r["log_snippet"] for r in rows]
        query = json.dumps(log_event, default=str)

        try:
            vectorizer = TfidfVectorizer(
                analyzer="word",
                ngram_range=(1, 2),
                min_df=1,
                stop_words="english",
            )
            tfidf_matrix = vectorizer.fit_transform(corpus + [query])
            scores = cosine_similarity(tfidf_matrix[-1], tfidf_matrix[:-1])[0]
        except ValueError:
            # Corpus too small for vectorizer
            return []

        # Filter by threshold and sort descending
        ranked = sorted(
            ((float(s), rows[i]) for i, s in enumerate(scores) if s >= self._threshold),
            key=lambda x: x[0],
            reverse=True,
        )[:limit]

        results = []
        for score, row in ranked:
            results.append(
                {
                    "case_id": row["id"],
                    "log_snippet": row["log_snippet"],
                    "root_cause": row["root_cause"],
                    "solution": row["solution"],
                    "user_feedback": row["user_feedback"],
                    "confidence": row["confidence"],
                    "similarity": score,
                }
            )
        return results

    # ------------------------------------------------------------------
    # Alert logging
    # ------------------------------------------------------------------

    def log_alert(
        self,
        case_id: int,
        channel: str,
        status: str,
        details: str = "",
    ) -> None:
        """Record that an alert was fired for a case."""
        now = datetime.now(timezone.utc).isoformat()
        self._conn.execute(
            "INSERT INTO alerts (case_id, fired_at, channel, status, details) VALUES (?,?,?,?,?)",
            (case_id, now, channel, status, details),
        )
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()
