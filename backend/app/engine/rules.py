from collections.abc import Iterable


SOCIAL_ENGINEERING_TERMS = {
    "clearance": 320,
    "escrow": 260,
    "digital arrest": 420,
    "kyc update": 320,
    "refund": 140,
    "cashback": 90,
    "verification": 140,
    "police": 260,
    "government": 260,
    "trai": 300,
}


def clamp(score: float, low: int = 0, high: int = 1000) -> int:
    return max(low, min(high, int(score)))


def capped_sum(values: Iterable[int], high: int = 1000) -> int:
    return min(high, sum(values))
