"""Deterministic, explainable risk scoring.

The score is a transparent additive model, not a learned model. Every point in the
final score is attributable to a factor returned to the caller. This makes the
output auditable and reproducible across model/provider changes.
"""

from __future__ import annotations

from .models import (
    AssetCriticality,
    Confidence,
    CvssData,
    EpssScore,
    KevEntry,
    RiskAssessment,
    RiskBand,
    RiskFactor,
)

POLICY_VERSION = "risk-v1"

MAX_CVSS_POINTS = 50.0
MAX_EPSS_POINTS = 15.0
MAX_KEV_POINTS = 25.0
MAX_ASSET_POINTS = 10.0
KEV_FLOOR = 60.0

ASSET_POINTS: dict[AssetCriticality, float] = {
    AssetCriticality.LOW: 1.0,
    AssetCriticality.MEDIUM: 3.0,
    AssetCriticality.HIGH: 6.0,
    AssetCriticality.CRITICAL: 10.0,
}

BAND_THRESHOLDS: tuple[tuple[float, RiskBand], ...] = (
    (80.0, RiskBand.CRITICAL),
    (60.0, RiskBand.HIGH),
    (40.0, RiskBand.MEDIUM),
    (20.0, RiskBand.LOW),
)


def band_for(score: float) -> RiskBand:
    for threshold, band in BAND_THRESHOLDS:
        if score >= threshold:
            return band
    return RiskBand.INFO


def assess_risk(
    *,
    cvss: CvssData | None,
    epss: EpssScore | None,
    kev: KevEntry | None,
    asset_criticality: AssetCriticality,
) -> RiskAssessment:
    """Compute a 0-100 score with explicit factor contributions.

    Missing data never invents evidence: the factor is emitted with zero
    contribution and the confidence drops. A known-exploited vulnerability receives
    a documented floor of 60 (high), because observed exploitation outweighs a
    possibly-stale CVSS base score.
    """
    factors: list[RiskFactor] = []
    score = 0.0
    available_weight = 0.0

    if cvss is not None:
        contribution = (cvss.base_score / 10.0) * MAX_CVSS_POINTS
        score += contribution
        available_weight += 0.45
        factors.append(
            RiskFactor(
                name="cvss_base",
                weight=MAX_CVSS_POINTS,
                contribution=round(contribution, 2),
                detail=f"CVSS {cvss.version} base {cvss.base_score:.1f} from {cvss.source}",
            )
        )
    else:
        factors.append(
            RiskFactor(
                name="cvss_base",
                weight=MAX_CVSS_POINTS,
                contribution=0.0,
                detail="No CVSS data available; score is under-informed",
            )
        )

    if epss is not None:
        contribution = epss.score * MAX_EPSS_POINTS
        score += contribution
        available_weight += 0.25
        factors.append(
            RiskFactor(
                name="epss",
                weight=MAX_EPSS_POINTS,
                contribution=round(contribution, 2),
                detail=(
                    f"EPSS {epss.score:.3f} (percentile {epss.percentile if epss.percentile is not None else 'n/a'})"
                ),
            )
        )
    else:
        factors.append(
            RiskFactor(
                name="epss",
                weight=MAX_EPSS_POINTS,
                contribution=0.0,
                detail="No EPSS forecast available",
            )
        )

    if kev is not None:
        score += MAX_KEV_POINTS
        available_weight += 0.2
        factors.append(
            RiskFactor(
                name="known_exploited",
                weight=MAX_KEV_POINTS,
                contribution=MAX_KEV_POINTS,
                detail=f"Listed in CISA KEV; ransomware use={kev.known_ransomware_use}",
            )
        )
    else:
        factors.append(
            RiskFactor(
                name="known_exploited",
                weight=MAX_KEV_POINTS,
                contribution=0.0,
                detail="Not present in the cached CISA KEV catalog",
            )
        )

    asset_points = ASSET_POINTS[asset_criticality]
    score += asset_points
    available_weight += 0.1
    factors.append(
        RiskFactor(
            name="asset_criticality",
            weight=MAX_ASSET_POINTS,
            contribution=asset_points,
            detail=f"Caller-declared asset criticality: {asset_criticality.value}",
        )
    )

    if kev is not None and score < KEV_FLOOR:
        delta = KEV_FLOOR - score
        score = KEV_FLOOR
        factors.append(
            RiskFactor(
                name="known_exploited_floor",
                weight=KEV_FLOOR,
                contribution=round(delta, 2),
                detail="Known-exploited floor raises the score to 60 (high)",
            )
        )

    score = round(min(score, 100.0), 1)
    band = band_for(score)
    confidence = (
        Confidence.HIGH
        if available_weight >= 0.85
        else Confidence.MEDIUM
        if available_weight >= 0.55
        else Confidence.LOW
    )
    sources_present = sum(x is not None for x in (cvss, epss, kev))
    rationale = (
        f"Additive {POLICY_VERSION} score {score:.1f}/100 ({band.value}); "
        f"exploitation signals present: {sources_present}/3; "
        f"asset criticality {asset_criticality.value}. "
        "Score is decision support and requires human validation."
    )
    return RiskAssessment(
        score=score,
        band=band,
        confidence=confidence,
        factors=factors,
        rationale=rationale,
        policy_version=POLICY_VERSION,
    )


def policy_document() -> dict[str, object]:
    """Machine-readable policy exposed as an MCP resource."""
    return {
        "policy_version": POLICY_VERSION,
        "description": "Transparent additive risk model for agentic triage",
        "weights": {
            "cvss_base": MAX_CVSS_POINTS,
            "epss": MAX_EPSS_POINTS,
            "known_exploited": MAX_KEV_POINTS,
            "asset_criticality": MAX_ASSET_POINTS,
        },
        "asset_points": {key.value: value for key, value in ASSET_POINTS.items()},
        "known_exploited_floor": KEV_FLOOR,
        "bands": [{"min_score": threshold, "band": band.value} for threshold, band in BAND_THRESHOLDS]
        + [{"min_score": 0.0, "band": "info"}],
        "limitations": [
            "Not a predictive model; CVSS/EPSS/KEV can be stale or unavailable.",
            "Asset exposure is caller-declared and not discovered by this server.",
            "KEV floor can make the reported score exceed the sum of factor contributions.",
        ],
    }
