"""The risk model must be deterministic, explainable, and monotonic."""

from __future__ import annotations

import pytest

from aegis_mcp.domain.models import (
    AssetCriticality,
    Confidence,
    CvssData,
    EpssScore,
    KevEntry,
    RiskBand,
)
from aegis_mcp.domain.risk import (
    KEV_FLOOR,
    MAX_ASSET_POINTS,
    MAX_CVSS_POINTS,
    MAX_EPSS_POINTS,
    MAX_KEV_POINTS,
    assess_risk,
    band_for,
    policy_document,
)


def _cvss(score: float) -> CvssData:
    return CvssData(version="3.1", base_score=score)


def _epss(score: float) -> EpssScore:
    return EpssScore(score=score)


def _kev() -> KevEntry:
    return KevEntry(cve_id="CVE-2021-44228", vendor="Apache", product="Log4j2", name="Log4j RCE")


@pytest.mark.parametrize(
    ("score", "band"),
    [
        (100, RiskBand.CRITICAL),
        (80, RiskBand.CRITICAL),
        (79.9, RiskBand.HIGH),
        (60, RiskBand.HIGH),
        (59.9, RiskBand.MEDIUM),
        (40, RiskBand.MEDIUM),
        (39.9, RiskBand.LOW),
        (20, RiskBand.LOW),
        (19.9, RiskBand.INFO),
    ],
)
def test_band_thresholds(score: float, band: RiskBand) -> None:
    assert band_for(score) is band


def test_weights_sum_to_one_hundred() -> None:
    assert MAX_CVSS_POINTS + MAX_EPSS_POINTS + MAX_KEV_POINTS + MAX_ASSET_POINTS == 100


def test_full_evidence_is_critical_and_high_confidence() -> None:
    assessment = assess_risk(
        cvss=_cvss(10.0),
        epss=_epss(0.97),
        kev=_kev(),
        asset_criticality=AssetCriticality.CRITICAL,
    )
    assert assessment.score == pytest.approx(99.55, abs=0.05)
    assert assessment.band is RiskBand.CRITICAL
    assert assessment.confidence is Confidence.HIGH
    contributions = {factor.name: factor.contribution for factor in assessment.factors}
    assert contributions["cvss_base"] == 50
    assert contributions["known_exploited"] == 25
    assert contributions["asset_criticality"] == 10


def test_kev_floor_raises_low_scores() -> None:
    assessment = assess_risk(
        cvss=_cvss(1.0),
        epss=_epss(0.0),
        kev=_kev(),
        asset_criticality=AssetCriticality.LOW,
    )
    assert assessment.score >= KEV_FLOOR
    assert any(factor.name == "known_exploited_floor" for factor in assessment.factors)
    assert assessment.band is RiskBand.HIGH


def test_missing_evidence_never_invents_points() -> None:
    assessment = assess_risk(
        cvss=None,
        epss=None,
        kev=None,
        asset_criticality=AssetCriticality.LOW,
    )
    assert assessment.score == 1.0
    assert assessment.confidence is Confidence.LOW
    reasons = {factor.name: factor.detail for factor in assessment.factors}
    assert "No CVSS" in reasons["cvss_base"]
    assert "No EPSS" in reasons["epss"]
    assert "Not present" in reasons["known_exploited"]


def test_monotonic_in_each_signal() -> None:
    low = assess_risk(cvss=_cvss(4.0), epss=_epss(0.1), kev=None, asset_criticality=AssetCriticality.MEDIUM)
    high = assess_risk(cvss=_cvss(8.0), epss=_epss(0.9), kev=None, asset_criticality=AssetCriticality.MEDIUM)
    assert high.score > low.score


def test_asset_criticality_increases_score() -> None:
    scores = [
        assess_risk(cvss=_cvss(7.0), epss=None, kev=None, asset_criticality=criticality).score
        for criticality in AssetCriticality
    ]
    assert scores == sorted(scores)


def test_score_is_capped_at_one_hundred() -> None:
    assessment = assess_risk(
        cvss=_cvss(10.0),
        epss=_epss(1.0),
        kev=_kev(),
        asset_criticality=AssetCriticality.CRITICAL,
    )
    assert assessment.score <= 100.0


def test_rationale_is_explainable() -> None:
    assessment = assess_risk(cvss=_cvss(9.8), epss=None, kev=None, asset_criticality=AssetCriticality.HIGH)
    assert assessment.policy_version == "risk-v1"
    assert "3 exploitation signals" not in assessment.rationale
    assert "1/3" in assessment.rationale
    assert "human validation" in assessment.rationale


def test_policy_document_shape() -> None:
    document = policy_document()
    assert document["policy_version"] == "risk-v1"
    assert document["known_exploited_floor"] == KEV_FLOOR
    assert document["weights"] == {
        "cvss_base": MAX_CVSS_POINTS,
        "epss": MAX_EPSS_POINTS,
        "known_exploited": MAX_KEV_POINTS,
        "asset_criticality": MAX_ASSET_POINTS,
    }
    assert document["asset_points"]["critical"] == 10
    assert document["bands"][-1] == {"min_score": 0.0, "band": "info"}
    assert document["limitations"]
