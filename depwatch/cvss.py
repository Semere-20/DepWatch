"""Calculate a CVSS v3.x base score from a vector string, with no extra libraries.

Why this file exists:
    OSV gives us a CVSS "vector" like
        CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
    but not the number (9.8). The number is what we rank by, so we compute it
    ourselves using the official formula from the CVSS v3.1 specification
    (https://www.first.org/cvss/v3.1/specification-document, section 7).

How to read a vector: each "KEY:VALUE" pair answers one question.
    AV  Attack Vector        - from where?   N=network A=adjacent L=local P=physical
    AC  Attack Complexity    - how hard?      L=low H=high
    PR  Privileges Required  - login needed?  N=none L=low H=high
    UI  User Interaction     - victim must click?  N=none R=required
    S   Scope                - can it escape to other components?  U=unchanged C=changed
    C/I/A  Confidentiality / Integrity / Availability impact: H=high L=low N=none
"""

from __future__ import annotations

import math

# The 8 metrics every v3 base vector must contain.
BASE_METRICS = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

# Official weights from the CVSS v3.1 spec (section 7.4).
ATTACK_VECTOR = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
ATTACK_COMPLEXITY = {"L": 0.77, "H": 0.44}
USER_INTERACTION = {"N": 0.85, "R": 0.62}
IMPACT = {"H": 0.56, "L": 0.22, "N": 0.0}  # used for C, I and A
# Privileges Required weights depend on Scope (a "changed" scope makes privileges matter less).
PRIVILEGES_SCOPE_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
PRIVILEGES_SCOPE_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.5}

# Allowed values for each metric, used to validate the vector.
ALLOWED_VALUES = {
    "AV": set(ATTACK_VECTOR),
    "AC": set(ATTACK_COMPLEXITY),
    "PR": set(PRIVILEGES_SCOPE_UNCHANGED),
    "UI": set(USER_INTERACTION),
    "S": {"U", "C"},
    "C": set(IMPACT),
    "I": set(IMPACT),
    "A": set(IMPACT),
}


def roundup(value: float) -> float:
    """Round UP to one decimal place, the way the CVSS v3.1 spec defines it.

    Example: 4.02 -> 4.1, 4.00 -> 4.0. The spec works in whole numbers
    (multiplying by 100,000) to avoid tiny floating-point errors such as
    4.000000000001 being rounded up to 4.1 by mistake.

    Args:
        value: Any non-negative number.

    Returns:
        The smallest number with one decimal that is >= value.
    """
    int_input = round(value * 100_000)
    if int_input % 10_000 == 0:
        return int_input / 100_000
    return (math.floor(int_input / 10_000) + 1) / 10.0


def parse_vector(vector: str) -> dict[str, str]:
    """Split a CVSS v3.x vector string into a {metric: value} dict.

    Args:
        vector: e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H".

    Returns:
        e.g. {"AV": "N", "AC": "L", ...}. Extra (temporal/environmental) metrics
        are kept in the dict but ignored by the base-score formula.

    Raises:
        ValueError: if the prefix is not CVSS:3.0 or CVSS:3.1, a part is malformed,
            or a base metric is missing or has an invalid value.
    """
    parts = vector.strip().split("/")
    if parts[0] not in ("CVSS:3.0", "CVSS:3.1"):
        raise ValueError(f"not a CVSS v3 vector: {vector!r}")

    metrics: dict[str, str] = {}
    for part in parts[1:]:
        key, sep, value = part.partition(":")  # "AV:N" -> ("AV", ":", "N")
        if not sep or not key or not value:
            raise ValueError(f"malformed part {part!r} in {vector!r}")
        metrics[key] = value

    for metric in BASE_METRICS:
        if metrics.get(metric) not in ALLOWED_VALUES[metric]:
            raise ValueError(f"missing or invalid {metric} in {vector!r}")
    return metrics


def base_score(vector: str) -> float:
    """Calculate the CVSS v3.x base score (0.0 - 10.0) for a vector string.

    Steps (from the spec):
        1. ISS (impact sub-score) = 1 - (1-C) * (1-I) * (1-A)
        2. Impact = 6.42 * ISS                                   if scope unchanged
                  = 7.52*(ISS-0.029) - 3.25*(ISS-0.02)**15       if scope changed
        3. Exploitability = 8.22 * AV * AC * PR * UI
        4. If Impact <= 0 the score is 0. Otherwise:
             unchanged: roundup(min(Impact + Exploitability, 10))
             changed:   roundup(min(1.08 * (Impact + Exploitability), 10))

    Args:
        vector: A CVSS v3.0 or v3.1 vector string.

    Returns:
        The base score, e.g. 9.8.

    Raises:
        ValueError: if the vector is invalid (see parse_vector).
    """
    m = parse_vector(vector)
    scope_changed = m["S"] == "C"

    # Step 1: how much damage to C, I and A combined.
    iss = 1 - (1 - IMPACT[m["C"]]) * (1 - IMPACT[m["I"]]) * (1 - IMPACT[m["A"]])

    # Step 2: impact, adjusted for scope.
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    # Step 3: how easy it is to exploit.
    privileges = (PRIVILEGES_SCOPE_CHANGED if scope_changed else PRIVILEGES_SCOPE_UNCHANGED)[m["PR"]]
    exploitability = (
        8.22 * ATTACK_VECTOR[m["AV"]] * ATTACK_COMPLEXITY[m["AC"]] * privileges * USER_INTERACTION[m["UI"]]
    )

    # Step 4: combine.
    if impact <= 0:
        return 0.0
    if scope_changed:
        return roundup(min(1.08 * (impact + exploitability), 10))
    return roundup(min(impact + exploitability, 10))


def score_to_level(score: float) -> str | None:
    """Map a numeric CVSS score to a severity level name.

    Bands (CVSS v3 qualitative rating scale):
        9.0-10.0 Critical, 7.0-8.9 High, 4.0-6.9 Medium, 0.1-3.9 Low.

    Args:
        score: A base score between 0.0 and 10.0.

    Returns:
        "Critical", "High", "Medium" or "Low"; or None for 0.0, which has no band
        here (the spec calls it "None"), so the caller falls back to other rules.
    """
    if score >= 9.0:
        return "Critical"
    if score >= 7.0:
        return "High"
    if score >= 4.0:
        return "Medium"
    if score >= 0.1:
        return "Low"
    return None
