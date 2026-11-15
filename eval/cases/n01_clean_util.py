def mean(values):
    if not values:
        raise ValueError("empty input")
    return sum(values) / len(values)


def clamp(x, lo, hi):
    return max(lo, min(x, hi))
