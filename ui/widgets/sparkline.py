from collections import deque
from typing import Sequence

BRAILLE_BARS = [" ", " ", "▂", "▃", "▄", "▅", "▆", "▇", "█"]

def render_sparkline(values: Sequence[float], min_val: float = 0.0, max_val: float = 100.0, width: int = 24) -> str:
    """Renders a sparkline string from a sequence of float values using block characters."""
    if not values:
        return " " * width
        
    # Take last `width` values
    recent = list(values)[-width:]
    
    # Pad left if fewer than width
    if len(recent) < width:
        recent = [min_val] * (width - len(recent)) + recent
        
    chars = []
    val_range = max(max_val - min_val, 0.001)
    
    for v in recent:
        clamped = max(min_val, min(max_val, v))
        norm = (clamped - min_val) / val_range
        idx = int(norm * (len(BRAILLE_BARS) - 1))
        chars.append(BRAILLE_BARS[idx])
        
    return "".join(chars)
