from dataclasses import dataclass
from typing import Literal


Action = Literal["ALLOW", "CHALLENGE", "BLOCK"]


@dataclass
class LayerScores:
    behavioral: int
    identity: int
    transaction: int
    remark: int


WEIGHTS = {
    "behavioral": 0.35,
    "identity": 0.25,
    "transaction": 0.30,
    "remark": 0.10,
}


def combine_scores(scores: LayerScores) -> tuple[int, Action]:
    final = int(
        scores.behavioral * WEIGHTS["behavioral"]
        + scores.identity * WEIGHTS["identity"]
        + scores.transaction * WEIGHTS["transaction"]
        + scores.remark * WEIGHTS["remark"]
    )

    if final <= 300:
        action: Action = "ALLOW"
    elif final <= 700:
        action = "CHALLENGE"
    else:
        action = "BLOCK"

    return final, action
