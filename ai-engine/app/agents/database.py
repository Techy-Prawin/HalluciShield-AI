"""
Database layer for PostgreSQL persistence.

Uses SQLAlchemy async engine for patch candidate storage.
Falls back gracefully if PostgreSQL is unavailable.
"""

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import List, Optional

from sqlalchemy import Column, String, Text, Float, Integer, DateTime, Index, JSON
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


class PatchCandidateRow(Base):
    __tablename__ = "patch_candidates"

    id = Column(String(64), primary_key=True, default=lambda: f"patch-{uuid.uuid4().hex[:12]}")
    vulnerability_id = Column(String(128), nullable=False, index=True)
    patch_id = Column(String(64), nullable=False)
    modified_code = Column(Text, nullable=False)
    explanation = Column(Text, nullable=False)
    security_strategy = Column(Text, nullable=False)
    assumptions = Column(Text, nullable=False, default="[]")
    expected_effect = Column(Text, nullable=False)
    potential_side_effects = Column(Text, nullable=False, default="[]")
    model_used = Column(String(128), nullable=False, default="unknown")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_patch_candidates_vuln_id", "vulnerability_id"),
    )


class ValidationResultRow(Base):
    __tablename__ = "validation_results"

    id = Column(String(64), primary_key=True, default=lambda: f"val-{uuid.uuid4().hex[:12]}")
    vulnerability_id = Column(String(128), nullable=False, index=True)
    patch_id = Column(String(64), nullable=False)
    validation_status = Column(String(16), nullable=False)
    compilation_score = Column(Float, nullable=False, default=0.0)
    unit_test_score = Column(Float, nullable=False, default=0.0)
    regression_score = Column(Float, nullable=False, default=0.0)
    security_score = Column(Float, nullable=False, default=0.0)
    functional_score = Column(Float, nullable=False, default=0.0)
    performance_score = Column(Float, nullable=False, default=0.0)
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_validation_results_vuln_id", "vulnerability_id"),
        Index("ix_validation_results_patch_id", "patch_id"),
    )


class ConfidenceResultRow(Base):
    __tablename__ = "confidence_results"

    id = Column(String(64), primary_key=True, default=lambda: f"conf-{uuid.uuid4().hex[:12]}")
    vulnerability_id = Column(String(128), nullable=False, index=True)
    patch_id = Column(String(64), nullable=False, index=True)
    confidence_score = Column(Float, nullable=False, default=0.0)
    feature_scores = Column(JSON, nullable=True)
    weights_used = Column(JSON, nullable=True)
    positive_evidence = Column(JSON, nullable=True)
    negative_evidence = Column(JSON, nullable=True)
    validation_failures = Column(JSON, nullable=True)
    recommendation = Column(Text, nullable=True)
    algorithm_version = Column(String(32), nullable=False, default="v1.0")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_confidence_results_vuln_id", "vulnerability_id"),
        Index("ix_confidence_results_patch_id", "patch_id"),
    )


class ConfidenceHistoryRow(Base):
    __tablename__ = "confidence_history"

    id = Column(String(64), primary_key=True, default=lambda: f"hist-{uuid.uuid4().hex[:12]}")
    vulnerability_id = Column(String(128), nullable=False, index=True)
    patch_id = Column(String(64), nullable=False)
    confidence_score = Column(Float, nullable=False, default=0.0)
    feature_scores = Column(JSON, nullable=True)
    weights_used = Column(JSON, nullable=True)
    algorithm_version = Column(String(32), nullable=False, default="v1.0")
    experiment_name = Column(String(128), nullable=True, index=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_confidence_history_vuln_id", "vulnerability_id"),
        Index("ix_confidence_history_experiment", "experiment_name"),
    )


class PatchApprovalRow(Base):
    __tablename__ = "patch_approvals"

    id = Column(String(64), primary_key=True, default=lambda: f"appr-{uuid.uuid4().hex[:12]}")
    vulnerability_id = Column(String(128), nullable=False, index=True)
    patch_id = Column(String(64), nullable=False, index=True)
    decision = Column(String(16), nullable=False)
    developer_id = Column(String(128), nullable=False)
    confidence_score = Column(Float, nullable=False, default=0.0)
    vulnerability_type = Column(String(128), nullable=True)
    patch_strategy = Column(Text, nullable=True)
    rejection_reason = Column(Text, nullable=True)
    approved_at = Column(DateTime(timezone=True), nullable=True)
    rejected_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_patch_approvals_vuln_id", "vulnerability_id"),
        Index("ix_patch_approvals_patch_id", "patch_id"),
        Index("ix_patch_approvals_developer", "developer_id"),
    )


class LearningRecordRow(Base):
    __tablename__ = "learning_records"

    id = Column(String(64), primary_key=True, default=lambda: f"learn-{uuid.uuid4().hex[:12]}")
    vulnerability_id = Column(String(128), nullable=False, index=True)
    patch_id = Column(String(64), nullable=False, index=True)
    vulnerability_type = Column(String(128), nullable=True, index=True)
    patch_strategy = Column(String(128), nullable=True, index=True)
    validation_features = Column(JSON, nullable=True)
    confidence_score = Column(Float, nullable=False, default=0.0)
    developer_decision = Column(String(16), nullable=True)
    developer_id = Column(String(128), nullable=True)
    rejection_reason = Column(Text, nullable=True)
    deployment_outcome = Column(String(16), nullable=True, default="UNKNOWN")
    deployment_notes = Column(Text, nullable=True)
    model_version = Column(String(32), nullable=False, default="v1.0")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_learning_records_vuln_id", "vulnerability_id"),
        Index("ix_learning_records_vuln_type", "vulnerability_type"),
        Index("ix_learning_records_strategy", "patch_strategy"),
    )


class LearningPatternRow(Base):
    __tablename__ = "learning_patterns"

    id = Column(String(64), primary_key=True, default=lambda: f"pat-{uuid.uuid4().hex[:12]}")
    vulnerability_type = Column(String(128), nullable=False)
    patch_strategy = Column(String(128), nullable=False)
    sample_count = Column(Integer, nullable=False, default=0)
    acceptance_rate = Column(Float, nullable=False, default=0.0)
    average_confidence = Column(Float, nullable=False, default=0.0)
    deployment_success_rate = Column(Float, nullable=False, default=0.0)
    historical_weight = Column(Float, nullable=False, default=0.5)
    confidence_interval_lower = Column(Float, nullable=False, default=0.0)
    confidence_interval_upper = Column(Float, nullable=False, default=1.0)
    last_updated = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    model_version = Column(String(32), nullable=False, default="v1.0")

    __table_args__ = (
        Index("ix_learning_patterns_vuln_type", "vulnerability_type"),
        Index("ix_learning_patterns_strategy", "patch_strategy"),
        Index("ix_learning_patterns_type_strategy", "vulnerability_type", "patch_strategy"),
    )


class WeightAdjustmentRow(Base):
    __tablename__ = "weight_adjustments"

    id = Column(String(64), primary_key=True, default=lambda: f"adj-{uuid.uuid4().hex[:12]}")
    previous_weights = Column(JSON, nullable=True)
    new_weights = Column(JSON, nullable=True)
    reason = Column(Text, nullable=True)
    patterns_used = Column(JSON, nullable=True)
    performance_before = Column(Float, nullable=False, default=0.0)
    performance_after = Column(Float, nullable=False, default=0.0)
    model_version = Column(String(32), nullable=False, default="v1.0")
    adjusted_by = Column(String(128), nullable=False, default="system")
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_weight_adjustments_model_version", "model_version"),
    )


class RuntimeEventRow(Base):
    __tablename__ = "runtime_events"

    id = Column(String(64), primary_key=True, default=lambda: f"evt-{uuid.uuid4().hex[:12]}")
    event_type = Column(String(32), nullable=False, index=True)
    severity = Column(String(16), nullable=False, index=True)
    source = Column(String(128), nullable=True)
    description = Column(Text, nullable=True)
    endpoint = Column(String(256), nullable=True, index=True)
    method = Column(String(16), nullable=True)
    status_code = Column(Integer, nullable=True)
    response_time_ms = Column(Integer, nullable=True)
    error_message = Column(Text, nullable=True)
    client_ip = Column(String(64), nullable=True)
    user_agent = Column(Text, nullable=True)
    request_count = Column(Integer, nullable=False, default=1)
    time_window_seconds = Column(Integer, nullable=False, default=0)
    metadata_ = Column("metadata", JSON, nullable=True)
    model_version = Column(String(32), nullable=False, default="v1.0")
    detected_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_runtime_events_type_severity", "event_type", "severity"),
        Index("ix_runtime_events_detected_at", "detected_at"),
    )


class SecurityAlertRow(Base):
    __tablename__ = "security_alerts"

    id = Column(String(64), primary_key=True, default=lambda: f"alert-{uuid.uuid4().hex[:12]}")
    event_id = Column(String(64), nullable=False, index=True)
    event_type = Column(String(32), nullable=False)
    severity = Column(String(16), nullable=False, index=True)
    vulnerability_type = Column(String(128), nullable=True)
    vulnerability_description = Column(Text, nullable=True)
    affected_endpoint = Column(String(256), nullable=True)
    risk_score = Column(Float, nullable=False, default=0.0)
    recommended_action = Column(Text, nullable=True)
    triggered_reanalysis = Column(Integer, nullable=False, default=0)
    patch_generated = Column(Integer, nullable=False, default=0)
    patch_validated = Column(Integer, nullable=False, default=0)
    developer_notified = Column(Integer, nullable=False, default=0)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        Index("ix_security_alerts_event_id", "event_id"),
        Index("ix_security_alerts_severity", "severity"),
    )


class ResearchExperimentRow(Base):
    __tablename__ = "research_experiments"

    id = Column(String(64), primary_key=True, default=lambda: f"exp-{uuid.uuid4().hex[:12]}")
    experiment_id = Column(String(100), nullable=False, index=True)
    sample_id = Column(String(100), nullable=True, index=True)
    name = Column(String(255), nullable=False)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    configuration_version = Column(String(50), nullable=False, default="v1.0")
    model_provider = Column(String(100), nullable=True, default="unknown")
    code_hash = Column(String(128), nullable=True)
    patch_hash = Column(String(128), nullable=True)
    metadata_json = Column(JSON, nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AECEScoreRow(Base):
    __tablename__ = "aece_scores"

    id = Column(String(64), primary_key=True, default=lambda: f"aece-{uuid.uuid4().hex[:12]}")
    patch_id = Column(String(100), nullable=False, index=True)
    experiment_id = Column(String(100), nullable=True, index=True)
    sample_id = Column(String(100), nullable=True)
    legacy_ace_score = Column(Float, nullable=False)
    evidence_completeness = Column(Float, nullable=False)
    evidence_aware_confidence = Column(Float, nullable=False)
    decision = Column(String(50), nullable=False, index=True)
    recommendation = Column(Text, nullable=True)
    dimension_scores = Column(JSON, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    configuration_version = Column(String(50), nullable=False, default="v1.0")
    model_provider = Column(String(100), nullable=True, default="unknown")
    code_hash = Column(String(128), nullable=True)
    patch_hash = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class CausalFindingRow(Base):
    __tablename__ = "causal_findings"

    id = Column(String(64), primary_key=True, default=lambda: f"causal-{uuid.uuid4().hex[:12]}")
    causal_id = Column(String(100), nullable=False, unique=True)
    experiment_id = Column(String(100), nullable=True, index=True)
    sample_id = Column(String(100), nullable=True)
    vulnerability_id = Column(String(100), nullable=False, index=True)
    hallucination_id = Column(String(100), nullable=True, index=True)
    category = Column(String(100), nullable=False, index=True)
    status = Column(String(50), nullable=False, index=True)
    cwe = Column(String(50), nullable=True)
    affected_symbol = Column(String(255), nullable=True)
    file_path = Column(Text, nullable=True)
    line_number = Column(Integer, nullable=True)
    causal_chain = Column(JSON, nullable=True)
    causal_evidence = Column(Text, nullable=True)
    attribution_type = Column(String(50), nullable=True, default="unknown")
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    configuration_version = Column(String(50), nullable=False, default="v1.0")
    model_provider = Column(String(100), nullable=True, default="unknown")
    code_hash = Column(String(128), nullable=True)
    patch_hash = Column(String(128), nullable=True)
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class PatchEvidenceRow(Base):
    __tablename__ = "patch_evidence"

    id = Column(String(64), primary_key=True, default=lambda: f"evi-{uuid.uuid4().hex[:12]}")
    patch_id = Column(String(100), nullable=False, index=True)
    experiment_id = Column(String(100), nullable=True, index=True)
    sample_id = Column(String(100), nullable=True)
    compilation_evidence = Column(JSON, nullable=True)
    unit_test_evidence = Column(JSON, nullable=True)
    regression_evidence = Column(JSON, nullable=True)
    security_evidence = Column(JSON, nullable=True)
    performance_evidence = Column(JSON, nullable=True)
    historical_evidence = Column(JSON, nullable=True)
    evidence_completeness = Column(Float, nullable=False, default=0.0)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    created_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


_engine = None
_session_factory = None


async def get_engine():
    global _engine
    if _engine is None:
        _engine = create_async_engine(
            settings.database_url,
            echo=False,
            pool_size=5,
            max_overflow=10,
        )
    return _engine


async def get_session_factory():
    global _session_factory
    if _session_factory is None:
        engine = await get_engine()
        _session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    return _session_factory


async def init_db():
    """Create tables if they don't exist."""
    try:
        engine = await get_engine()
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("[Database] Tables created/verified successfully")
    except Exception as e:
        logger.warning(f"[Database] Could not initialize PostgreSQL tables: {e}")
        logger.warning("[Database] Patch storage will use in-memory fallback")


async def store_patch_candidates(
    vulnerability_id: str,
    candidates: list,
    model_used: str,
) -> List[dict]:
    """
    Store patch candidates in PostgreSQL.

    Returns list of stored records (with IDs).
    Falls back to in-memory storage if DB is unavailable.
    """
    stored = []

    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            for candidate in candidates:
                row = PatchCandidateRow(
                    vulnerability_id=vulnerability_id,
                    patch_id=candidate.patch_id,
                    modified_code=candidate.modified_code,
                    explanation=candidate.explanation,
                    security_strategy=candidate.security_strategy,
                    assumptions=json.dumps(candidate.assumptions),
                    expected_effect=candidate.expected_effect,
                    potential_side_effects=json.dumps(candidate.potential_side_effects),
                    model_used=model_used,
                )
                session.add(row)
                await session.flush()
                stored.append({
                    "id": row.id,
                    "patch_id": row.patch_id,
                    "vulnerability_id": row.vulnerability_id,
                })
            await session.commit()
            logger.info(
                f"[Database] Stored {len(stored)} patch candidates for vulnerability {vulnerability_id}"
            )
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL storage failed: {e}. Using in-memory fallback.")
        for candidate in candidates:
            stored.append({
                "id": f"patch-{uuid.uuid4().hex[:12]}",
                "patch_id": candidate.patch_id,
                "vulnerability_id": vulnerability_id,
            })

    return stored


async def get_patch_candidates_by_vulnerability(vulnerability_id: str) -> List[dict]:
    """Retrieve all patch candidates for a given vulnerability ID."""
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            from sqlalchemy import select
            stmt = select(PatchCandidateRow).where(
                PatchCandidateRow.vulnerability_id == vulnerability_id
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()

            return [
                {
                    "id": row.id,
                    "patch_id": row.patch_id,
                    "vulnerability_id": row.vulnerability_id,
                    "modified_code": row.modified_code,
                    "explanation": row.explanation,
                    "security_strategy": row.security_strategy,
                    "assumptions": json.loads(row.assumptions),
                    "expected_effect": row.expected_effect,
                    "potential_side_effects": json.loads(row.potential_side_effects),
                    "model_used": row.model_used,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
                for row in rows
            ]
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL query failed: {e}")
        return []


# ============================================================
# Validation Result Storage
# ============================================================

_in_memory_validation_results: List[dict] = []


async def store_validation_result(
    result: dict,
) -> dict:
    """
    Store a validation result in PostgreSQL.

    Returns stored record with ID.
    Falls back to in-memory storage if DB is unavailable.
    """
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            row = ValidationResultRow(
                vulnerability_id=result["vulnerability_id"],
                patch_id=result["patch_id"],
                validation_status=result["validation_status"],
                compilation_score=result["compilation_score"],
                unit_test_score=result["unit_test_score"],
                regression_score=result["regression_score"],
                security_score=result["security_score"],
                functional_score=result["functional_score"],
                performance_score=result["performance_score"],
                details=result.get("details"),
            )
            session.add(row)
            await session.flush()
            stored = {
                "id": row.id,
                "patch_id": row.patch_id,
                "vulnerability_id": row.vulnerability_id,
                "validation_status": row.validation_status,
            }
            await session.commit()
            logger.info(
                f"[Database] Stored validation result {row.id} "
                f"for patch {result['patch_id']}"
            )
            return stored
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL storage failed: {e}. Using in-memory fallback.")
        stored = {
            "id": f"val-{uuid.uuid4().hex[:12]}",
            "patch_id": result["patch_id"],
            "vulnerability_id": result["vulnerability_id"],
            "validation_status": result["validation_status"],
        }
        _in_memory_validation_results.append({**result, **stored})
        return stored


async def store_validation_results_batch(
    results: List[dict],
) -> List[dict]:
    """Store multiple validation results in PostgreSQL."""
    stored = []
    for result in results:
        record = await store_validation_result(result)
        stored.append(record)
    return stored


async def get_validation_results_by_vulnerability(
    vulnerability_id: str,
) -> List[dict]:
    """Retrieve all validation results for a given vulnerability ID."""
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            from sqlalchemy import select
            stmt = select(ValidationResultRow).where(
                ValidationResultRow.vulnerability_id == vulnerability_id
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()

            return [
                {
                    "id": row.id,
                    "patch_id": row.patch_id,
                    "vulnerability_id": row.vulnerability_id,
                    "validation_status": row.validation_status,
                    "compilation_score": row.compilation_score,
                    "unit_test_score": row.unit_test_score,
                    "regression_score": row.regression_score,
                    "security_score": row.security_score,
                    "functional_score": row.functional_score,
                    "performance_score": row.performance_score,
                    "details": row.details,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
                for row in rows
            ]
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL query failed: {e}")
        # Fall back to in-memory storage
        return [
            r for r in _in_memory_validation_results
            if r.get("vulnerability_id") == vulnerability_id
        ]


async def get_validation_results_by_patch(
    patch_id: str,
) -> List[dict]:
    """Retrieve all validation results for a given patch ID."""
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            from sqlalchemy import select
            stmt = select(ValidationResultRow).where(
                ValidationResultRow.patch_id == patch_id
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()

            return [
                {
                    "id": row.id,
                    "patch_id": row.patch_id,
                    "vulnerability_id": row.vulnerability_id,
                    "validation_status": row.validation_status,
                    "compilation_score": row.compilation_score,
                    "unit_test_score": row.unit_test_score,
                    "regression_score": row.regression_score,
                    "security_score": row.security_score,
                    "functional_score": row.functional_score,
                    "performance_score": row.performance_score,
                    "details": row.details,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
                for row in rows
            ]
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL query failed: {e}")
        return [
            r for r in _in_memory_validation_results
            if r.get("patch_id") == patch_id
        ]


# ============================================================
# Confidence Result Storage
# ============================================================

_in_memory_confidence_results: List[dict] = []
_in_memory_confidence_history: List[dict] = []


async def store_confidence_result(
    result: dict,
) -> dict:
    """
    Store a confidence result in PostgreSQL.

    Returns stored record with ID.
    Falls back to in-memory storage if DB is unavailable.
    """
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            row = ConfidenceResultRow(
                vulnerability_id=result["vulnerability_id"],
                patch_id=result["patch_id"],
                confidence_score=result["confidence_score"],
                feature_scores=result.get("feature_scores"),
                weights_used=result.get("weights_used"),
                positive_evidence=result.get("positive_evidence"),
                negative_evidence=result.get("negative_evidence"),
                validation_failures=result.get("validation_failures"),
                recommendation=result.get("recommendation"),
                algorithm_version=result.get("algorithm_version", "v1.0"),
            )
            session.add(row)
            await session.flush()
            stored = {
                "id": row.id,
                "patch_id": row.patch_id,
                "vulnerability_id": row.vulnerability_id,
                "confidence_score": row.confidence_score,
            }
            await session.commit()
            logger.info(
                f"[Database] Stored confidence result {row.id} "
                f"for patch {result['patch_id']}: "
                f"{result['confidence_score']:.1f}%"
            )
            return stored
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL storage failed: {e}. Using in-memory fallback.")
        stored = {
            "id": f"conf-{uuid.uuid4().hex[:12]}",
            "patch_id": result["patch_id"],
            "vulnerability_id": result["vulnerability_id"],
            "confidence_score": result["confidence_score"],
        }
        _in_memory_confidence_results.append({**result, **stored})
        return stored


async def store_confidence_results_batch(
    results: List[dict],
) -> List[dict]:
    """Store multiple confidence results in PostgreSQL."""
    stored = []
    for result in results:
        record = await store_confidence_result(result)
        stored.append(record)
    return stored


async def store_confidence_history(
    result: dict,
    experiment_name: Optional[str] = None,
) -> dict:
    """
    Store confidence result in history for research experiments.
    """
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            row = ConfidenceHistoryRow(
                vulnerability_id=result["vulnerability_id"],
                patch_id=result["patch_id"],
                confidence_score=result["confidence_score"],
                feature_scores=result.get("feature_scores"),
                weights_used=result.get("weights_used"),
                algorithm_version=result.get("algorithm_version", "v1.0"),
                experiment_name=experiment_name,
            )
            session.add(row)
            await session.flush()
            stored = {
                "id": row.id,
                "patch_id": row.patch_id,
                "vulnerability_id": row.vulnerability_id,
                "confidence_score": row.confidence_score,
                "experiment_name": experiment_name,
            }
            await session.commit()
            return stored
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL history storage failed: {e}.")
        stored = {
            "id": f"hist-{uuid.uuid4().hex[:12]}",
            "patch_id": result["patch_id"],
            "vulnerability_id": result["vulnerability_id"],
            "confidence_score": result["confidence_score"],
            "experiment_name": experiment_name,
        }
        _in_memory_confidence_history.append({**result, **stored})
        return stored


async def get_confidence_results_by_vulnerability(
    vulnerability_id: str,
) -> List[dict]:
    """Retrieve all confidence results for a given vulnerability ID."""
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            from sqlalchemy import select
            stmt = select(ConfidenceResultRow).where(
                ConfidenceResultRow.vulnerability_id == vulnerability_id
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()

            return [
                {
                    "id": row.id,
                    "patch_id": row.patch_id,
                    "vulnerability_id": row.vulnerability_id,
                    "confidence_score": row.confidence_score,
                    "feature_scores": row.feature_scores,
                    "weights_used": row.weights_used,
                    "positive_evidence": row.positive_evidence,
                    "negative_evidence": row.negative_evidence,
                    "validation_failures": row.validation_failures,
                    "recommendation": row.recommendation,
                    "algorithm_version": row.algorithm_version,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
                for row in rows
            ]
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL query failed: {e}")
        return [
            r for r in _in_memory_confidence_results
            if r.get("vulnerability_id") == vulnerability_id
        ]


async def get_confidence_history(
    vulnerability_id: Optional[str] = None,
    experiment_name: Optional[str] = None,
    limit: int = 100,
) -> List[dict]:
    """Retrieve confidence history for research experiments."""
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            from sqlalchemy import select
            stmt = select(ConfidenceHistoryRow)
            if vulnerability_id:
                stmt = stmt.where(
                    ConfidenceHistoryRow.vulnerability_id == vulnerability_id
                )
            if experiment_name:
                stmt = stmt.where(
                    ConfidenceHistoryRow.experiment_name == experiment_name
                )
            stmt = stmt.order_by(ConfidenceHistoryRow.created_at.desc()).limit(limit)

            result = await session.execute(stmt)
            rows = result.scalars().all()

            return [
                {
                    "id": row.id,
                    "patch_id": row.patch_id,
                    "vulnerability_id": row.vulnerability_id,
                    "confidence_score": row.confidence_score,
                    "feature_scores": row.feature_scores,
                    "weights_used": row.weights_used,
                    "algorithm_version": row.algorithm_version,
                    "experiment_name": row.experiment_name,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
                for row in rows
            ]
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL query failed: {e}")
        filtered = _in_memory_confidence_history
        if vulnerability_id:
            filtered = [r for r in filtered if r.get("vulnerability_id") == vulnerability_id]
        if experiment_name:
            filtered = [r for r in filtered if r.get("experiment_name") == experiment_name]
        return filtered[:limit]


# ============================================================
# Patch Approval Storage
# ============================================================

_in_memory_patch_approvals: List[dict] = []


async def store_patch_approval(
    record: dict,
) -> dict:
    """
    Store a patch approval/rejection record in PostgreSQL.

    Returns stored record with ID.
    Falls back to in-memory storage if DB is unavailable.
    """
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            row = PatchApprovalRow(
                vulnerability_id=record["vulnerability_id"],
                patch_id=record["patch_id"],
                decision=record["decision"],
                developer_id=record["developer_id"],
                confidence_score=record.get("confidence_score", 0.0),
                vulnerability_type=record.get("vulnerability_type"),
                patch_strategy=record.get("patch_strategy"),
                rejection_reason=record.get("rejection_reason"),
            )
            session.add(row)
            await session.flush()
            stored = {
                "id": row.id,
                "patch_id": row.patch_id,
                "vulnerability_id": row.vulnerability_id,
                "decision": row.decision,
                "developer_id": row.developer_id,
            }
            await session.commit()
            logger.info(
                f"[Database] Stored patch approval {row.id}: "
                f"{row.decision} for patch {row.patch_id}"
            )
            return stored
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL storage failed: {e}. Using in-memory fallback.")
        stored = {
            "id": f"appr-{uuid.uuid4().hex[:12]}",
            "patch_id": record["patch_id"],
            "vulnerability_id": record["vulnerability_id"],
            "decision": record["decision"],
            "developer_id": record["developer_id"],
        }
        _in_memory_patch_approvals.append({**record, **stored})
        return stored


async def get_patch_approval_by_patch(
    vulnerability_id: str,
    patch_id: str,
) -> Optional[dict]:
    """Retrieve approval record for a specific patch."""
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            from sqlalchemy import select
            stmt = select(PatchApprovalRow).where(
                PatchApprovalRow.vulnerability_id == vulnerability_id,
                PatchApprovalRow.patch_id == patch_id,
            )
            result = await session.execute(stmt)
            row = result.scalar_one_or_none()

            if row is None:
                return None

            return {
                "id": row.id,
                "patch_id": row.patch_id,
                "vulnerability_id": row.vulnerability_id,
                "decision": row.decision,
                "developer_id": row.developer_id,
                "confidence_score": row.confidence_score,
                "vulnerability_type": row.vulnerability_type,
                "patch_strategy": row.patch_strategy,
                "rejection_reason": row.rejection_reason,
                "approved_at": row.approved_at.isoformat() if row.approved_at else None,
                "rejected_at": row.rejected_at.isoformat() if row.rejected_at else None,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL query failed: {e}")
        for r in _in_memory_patch_approvals:
            if r.get("vulnerability_id") == vulnerability_id and r.get("patch_id") == patch_id:
                return r
        return None


async def get_patch_approvals_by_vulnerability(
    vulnerability_id: str,
) -> List[dict]:
    """Retrieve all approval records for a vulnerability."""
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            from sqlalchemy import select
            stmt = select(PatchApprovalRow).where(
                PatchApprovalRow.vulnerability_id == vulnerability_id
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()

            return [
                {
                    "id": row.id,
                    "patch_id": row.patch_id,
                    "vulnerability_id": row.vulnerability_id,
                    "decision": row.decision,
                    "developer_id": row.developer_id,
                    "confidence_score": row.confidence_score,
                    "vulnerability_type": row.vulnerability_type,
                    "patch_strategy": row.patch_strategy,
                    "rejection_reason": row.rejection_reason,
                    "approved_at": row.approved_at.isoformat() if row.approved_at else None,
                    "rejected_at": row.rejected_at.isoformat() if row.rejected_at else None,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
                for row in rows
            ]
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL query failed: {e}")
        return [
            r for r in _in_memory_patch_approvals
            if r.get("vulnerability_id") == vulnerability_id
        ]


async def get_patch_approvals_by_developer(
    developer_id: str,
) -> List[dict]:
    """Retrieve all approval records for a developer."""
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            from sqlalchemy import select
            stmt = select(PatchApprovalRow).where(
                PatchApprovalRow.developer_id == developer_id
            )
            result = await session.execute(stmt)
            rows = result.scalars().all()

            return [
                {
                    "id": row.id,
                    "patch_id": row.patch_id,
                    "vulnerability_id": row.vulnerability_id,
                    "decision": row.decision,
                    "developer_id": row.developer_id,
                    "confidence_score": row.confidence_score,
                    "vulnerability_type": row.vulnerability_type,
                    "patch_strategy": row.patch_strategy,
                    "rejection_reason": row.rejection_reason,
                    "approved_at": row.approved_at.isoformat() if row.approved_at else None,
                    "rejected_at": row.rejected_at.isoformat() if row.rejected_at else None,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
                for row in rows
            ]
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL query failed: {e}")
        return [
            r for r in _in_memory_patch_approvals
            if r.get("developer_id") == developer_id
        ]


# ============================================================
# Learning Record Storage
# ============================================================

_in_memory_learning_records: List[dict] = []
_in_memory_learning_patterns: List[dict] = []
_in_memory_weight_adjustments: List[dict] = []


async def store_learning_record(record: dict) -> dict:
    """Store a learning record in PostgreSQL."""
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            row = LearningRecordRow(
                vulnerability_id=record["vulnerability_id"],
                patch_id=record["patch_id"],
                vulnerability_type=record.get("vulnerability_type"),
                patch_strategy=record.get("patch_strategy"),
                validation_features=record.get("validation_features"),
                confidence_score=record.get("confidence_score", 0.0),
                developer_decision=record.get("developer_decision"),
                developer_id=record.get("developer_id"),
                rejection_reason=record.get("rejection_reason"),
                deployment_outcome=record.get("deployment_outcome", "UNKNOWN"),
                deployment_notes=record.get("deployment_notes"),
                model_version=record.get("model_version", "v1.0"),
            )
            session.add(row)
            await session.flush()
            stored = {
                "id": row.id,
                "patch_id": row.patch_id,
                "vulnerability_id": row.vulnerability_id,
            }
            await session.commit()
            logger.info(f"[Database] Stored learning record {row.id}")
            return stored
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL storage failed: {e}. Using in-memory fallback.")
        stored = {
            "id": f"learn-{uuid.uuid4().hex[:12]}",
            "patch_id": record["patch_id"],
            "vulnerability_id": record["vulnerability_id"],
        }
        _in_memory_learning_records.append({**record, **stored})
        return stored


async def get_learning_records(
    vulnerability_type: Optional[str] = None,
    patch_strategy: Optional[str] = None,
    limit: int = 1000,
) -> List[dict]:
    """Retrieve learning records with optional filters."""
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            from sqlalchemy import select
            stmt = select(LearningRecordRow)
            if vulnerability_type:
                stmt = stmt.where(LearningRecordRow.vulnerability_type == vulnerability_type)
            if patch_strategy:
                stmt = stmt.where(LearningRecordRow.patch_strategy == patch_strategy)
            stmt = stmt.order_by(LearningRecordRow.created_at.desc()).limit(limit)
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [
                {
                    "id": row.id,
                    "vulnerability_id": row.vulnerability_id,
                    "patch_id": row.patch_id,
                    "vulnerability_type": row.vulnerability_type,
                    "patch_strategy": row.patch_strategy,
                    "validation_features": row.validation_features,
                    "confidence_score": row.confidence_score,
                    "developer_decision": row.developer_decision,
                    "developer_id": row.developer_id,
                    "rejection_reason": row.rejection_reason,
                    "deployment_outcome": row.deployment_outcome,
                    "deployment_notes": row.deployment_notes,
                    "model_version": row.model_version,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
                for row in rows
            ]
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL query failed: {e}")
        filtered = _in_memory_learning_records
        if vulnerability_type:
            filtered = [r for r in filtered if r.get("vulnerability_type") == vulnerability_type]
        if patch_strategy:
            filtered = [r for r in filtered if r.get("patch_strategy") == patch_strategy]
        return filtered[:limit]


async def store_learning_pattern(pattern: dict) -> dict:
    """Store or update a learning pattern."""
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            from sqlalchemy import select
            stmt = select(LearningPatternRow).where(
                LearningPatternRow.vulnerability_type == pattern["vulnerability_type"],
                LearningPatternRow.patch_strategy == pattern["patch_strategy"],
            )
            result = await session.execute(stmt)
            existing = result.scalar_one_or_none()

            if existing:
                existing.sample_count = pattern.get("sample_count", 0)
                existing.acceptance_rate = pattern.get("acceptance_rate", 0.0)
                existing.average_confidence = pattern.get("average_confidence", 0.0)
                existing.deployment_success_rate = pattern.get("deployment_success_rate", 0.0)
                existing.historical_weight = pattern.get("historical_weight", 0.5)
                existing.confidence_interval_lower = pattern.get("confidence_interval_lower", 0.0)
                existing.confidence_interval_upper = pattern.get("confidence_interval_upper", 1.0)
                existing.model_version = pattern.get("model_version", "v1.0")
                row_id = existing.id
            else:
                row = LearningPatternRow(
                    vulnerability_type=pattern["vulnerability_type"],
                    patch_strategy=pattern["patch_strategy"],
                    sample_count=pattern.get("sample_count", 0),
                    acceptance_rate=pattern.get("acceptance_rate", 0.0),
                    average_confidence=pattern.get("average_confidence", 0.0),
                    deployment_success_rate=pattern.get("deployment_success_rate", 0.0),
                    historical_weight=pattern.get("historical_weight", 0.5),
                    confidence_interval_lower=pattern.get("confidence_interval_lower", 0.0),
                    confidence_interval_upper=pattern.get("confidence_interval_upper", 1.0),
                    model_version=pattern.get("model_version", "v1.0"),
                )
                session.add(row)
                row_id = row.id
            await session.commit()
            return {"id": row_id, "vulnerability_type": pattern["vulnerability_type"]}
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL storage failed: {e}. Using in-memory fallback.")
        key = f"{pattern['vulnerability_type']}:{pattern['patch_strategy']}"
        for p in _in_memory_learning_patterns:
            if p.get("key") == key:
                p.update(pattern)
                return {"id": p.get("id", "pat-0"), "vulnerability_type": pattern["vulnerability_type"]}
        _in_memory_learning_patterns.append({**pattern, "key": key})
        return {"id": f"pat-{uuid.uuid4().hex[:12]}", "vulnerability_type": pattern["vulnerability_type"]}


async def get_learning_patterns(
    vulnerability_type: Optional[str] = None,
) -> List[dict]:
    """Retrieve learning patterns."""
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            from sqlalchemy import select
            stmt = select(LearningPatternRow)
            if vulnerability_type:
                stmt = stmt.where(LearningPatternRow.vulnerability_type == vulnerability_type)
            stmt = stmt.order_by(LearningPatternRow.sample_count.desc())
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [
                {
                    "id": row.id,
                    "vulnerability_type": row.vulnerability_type,
                    "patch_strategy": row.patch_strategy,
                    "sample_count": row.sample_count,
                    "acceptance_rate": row.acceptance_rate,
                    "average_confidence": row.average_confidence,
                    "deployment_success_rate": row.deployment_success_rate,
                    "historical_weight": row.historical_weight,
                    "confidence_interval_lower": row.confidence_interval_lower,
                    "confidence_interval_upper": row.confidence_interval_upper,
                    "model_version": row.model_version,
                    "last_updated": row.last_updated.isoformat() if row.last_updated else None,
                }
                for row in rows
            ]
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL query failed: {e}")
        filtered = _in_memory_learning_patterns
        if vulnerability_type:
            filtered = [r for r in filtered if r.get("vulnerability_type") == vulnerability_type]
        return filtered


async def store_weight_adjustment(adjustment: dict) -> dict:
    """Store a weight adjustment record."""
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            row = WeightAdjustmentRow(
                previous_weights=adjustment.get("previous_weights"),
                new_weights=adjustment.get("new_weights"),
                reason=adjustment.get("reason"),
                patterns_used=adjustment.get("patterns_used"),
                performance_before=adjustment.get("performance_before", 0.0),
                performance_after=adjustment.get("performance_after", 0.0),
                model_version=adjustment.get("model_version", "v1.0"),
                adjusted_by=adjustment.get("adjusted_by", "system"),
            )
            session.add(row)
            await session.flush()
            stored = {"id": row.id, "model_version": row.model_version}
            await session.commit()
            return stored
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL storage failed: {e}. Using in-memory fallback.")
        stored = {"id": f"adj-{uuid.uuid4().hex[:12]}", "model_version": adjustment.get("model_version", "v1.0")}
        _in_memory_weight_adjustments.append({**adjustment, **stored})
        return stored


async def get_weight_adjustments(limit: int = 50) -> List[dict]:
    """Retrieve weight adjustment history."""
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            from sqlalchemy import select
            stmt = select(WeightAdjustmentRow).order_by(
                WeightAdjustmentRow.created_at.desc()
            ).limit(limit)
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [
                {
                    "id": row.id,
                    "previous_weights": row.previous_weights,
                    "new_weights": row.new_weights,
                    "reason": row.reason,
                    "patterns_used": row.patterns_used,
                    "performance_before": row.performance_before,
                    "performance_after": row.performance_after,
                    "model_version": row.model_version,
                    "adjusted_by": row.adjusted_by,
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
                for row in rows
            ]
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL query failed: {e}")
        return _in_memory_weight_adjustments[:limit]


# ============================================================
# Runtime Event Storage
# ============================================================

_in_memory_runtime_events: List[dict] = []
_in_memory_security_alerts: List[dict] = []


async def store_runtime_event(event: dict) -> dict:
    """Store a runtime event in PostgreSQL."""
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            row = RuntimeEventRow(
                event_type=event["event_type"],
                severity=event["severity"],
                source=event.get("source", ""),
                description=event.get("description", ""),
                endpoint=event.get("endpoint", ""),
                method=event.get("method", ""),
                status_code=event.get("status_code"),
                response_time_ms=event.get("response_time_ms"),
                error_message=event.get("error_message"),
                client_ip=event.get("client_ip", ""),
                user_agent=event.get("user_agent", ""),
                request_count=event.get("request_count", 1),
                time_window_seconds=event.get("time_window_seconds", 0),
                metadata_=event.get("metadata"),
                model_version=event.get("model_version", "v1.0"),
            )
            session.add(row)
            await session.flush()
            stored = {"id": row.id, "event_type": row.event_type, "severity": row.severity}
            await session.commit()
            logger.info(f"[Database] Stored runtime event {row.id}: {row.event_type}")
            return stored
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL storage failed: {e}. Using in-memory fallback.")
        stored = {
            "id": f"evt-{uuid.uuid4().hex[:12]}",
            "event_type": event["event_type"],
            "severity": event["severity"],
        }
        _in_memory_runtime_events.append({**event, **stored})
        return stored


async def get_runtime_events(
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
) -> List[dict]:
    """Retrieve runtime events with optional filters."""
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            from sqlalchemy import select
            stmt = select(RuntimeEventRow)
            if event_type:
                stmt = stmt.where(RuntimeEventRow.event_type == event_type)
            if severity:
                stmt = stmt.where(RuntimeEventRow.severity == severity)
            stmt = stmt.order_by(RuntimeEventRow.detected_at.desc()).limit(limit)
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [
                {
                    "id": row.id,
                    "event_type": row.event_type,
                    "severity": row.severity,
                    "source": row.source,
                    "description": row.description,
                    "endpoint": row.endpoint,
                    "method": row.method,
                    "status_code": row.status_code,
                    "response_time_ms": row.response_time_ms,
                    "error_message": row.error_message,
                    "client_ip": row.client_ip,
                    "user_agent": row.user_agent,
                    "request_count": row.request_count,
                    "time_window_seconds": row.time_window_seconds,
                    "metadata": row.metadata_,
                    "model_version": row.model_version,
                    "detected_at": row.detected_at.isoformat() if row.detected_at else None,
                }
                for row in rows
            ]
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL query failed: {e}")
        filtered = _in_memory_runtime_events
        if event_type:
            filtered = [r for r in filtered if r.get("event_type") == event_type]
        if severity:
            filtered = [r for r in filtered if r.get("severity") == severity]
        return filtered[:limit]


async def store_security_alert(alert: dict) -> dict:
    """Store a security alert in PostgreSQL."""
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            row = SecurityAlertRow(
                event_id=alert["event_id"],
                event_type=alert["event_type"],
                severity=alert["severity"],
                vulnerability_type=alert.get("vulnerability_type", ""),
                vulnerability_description=alert.get("vulnerability_description", ""),
                affected_endpoint=alert.get("affected_endpoint", ""),
                risk_score=alert.get("risk_score", 0.0),
                recommended_action=alert.get("recommended_action", ""),
                triggered_reanalysis=1 if alert.get("triggered_reanalysis") else 0,
                patch_generated=1 if alert.get("patch_generated") else 0,
                patch_validated=1 if alert.get("patch_validated") else 0,
                developer_notified=1 if alert.get("developer_notified") else 0,
            )
            session.add(row)
            await session.flush()
            stored = {"id": row.id, "event_id": row.event_id, "severity": row.severity}
            await session.commit()
            logger.info(f"[Database] Stored security alert {row.id}")
            return stored
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL storage failed: {e}. Using in-memory fallback.")
        stored = {
            "id": f"alert-{uuid.uuid4().hex[:12]}",
            "event_id": alert["event_id"],
            "severity": alert["severity"],
        }
        _in_memory_security_alerts.append({**alert, **stored})
        return stored


async def get_security_alerts(
    event_type: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = 100,
) -> List[dict]:
    """Retrieve security alerts with optional filters."""
    try:
        session_factory = await get_session_factory()
        async with session_factory() as session:
            from sqlalchemy import select
            stmt = select(SecurityAlertRow)
            if event_type:
                stmt = stmt.where(SecurityAlertRow.event_type == event_type)
            if severity:
                stmt = stmt.where(SecurityAlertRow.severity == severity)
            stmt = stmt.order_by(SecurityAlertRow.created_at.desc()).limit(limit)
            result = await session.execute(stmt)
            rows = result.scalars().all()
            return [
                {
                    "id": row.id,
                    "event_id": row.event_id,
                    "event_type": row.event_type,
                    "severity": row.severity,
                    "vulnerability_type": row.vulnerability_type,
                    "vulnerability_description": row.vulnerability_description,
                    "affected_endpoint": row.affected_endpoint,
                    "risk_score": row.risk_score,
                    "recommended_action": row.recommended_action,
                    "triggered_reanalysis": bool(row.triggered_reanalysis),
                    "patch_generated": bool(row.patch_generated),
                    "patch_validated": bool(row.patch_validated),
                    "developer_notified": bool(row.developer_notified),
                    "created_at": row.created_at.isoformat() if row.created_at else None,
                }
                for row in rows
            ]
    except Exception as e:
        logger.warning(f"[Database] PostgreSQL query failed: {e}")
        filtered = _in_memory_security_alerts
        if event_type:
            filtered = [r for r in filtered if r.get("event_type") == event_type]
        if severity:
            filtered = [r for r in filtered if r.get("severity") == severity]
        return filtered[:limit]
