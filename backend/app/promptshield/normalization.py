"""
PromptShield normalization and multi-layer decoding (PS-05, spec §4.2).

- NFKC, casefold, drop Cf and zero-width characters, collapse whitespace.
- strip non-alphanumeric for protected value matching.
- Multi-layer decoders to depth 2: base64, hex, percent-encoding, unicode tags.
"""

from __future__ import annotations

import base64
import re
import unicodedata
import urllib.parse

ZERO_WIDTH_CHARS = {
    "\u200b", "\u200c", "\u200d", "\u200e", "\u200f",
    "\u2060", "\ufeff", "\u00ad",
}

BASE64_REGEX = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}|[A-Za-z0-9_-]{16,}={0,2}")
HEX_REGEX = re.compile(r"(?:[0-9a-fA-F]{2}){8,}")
PERCENT_REGEX = re.compile(r"(?:%[0-9A-Fa-f]{2}){4,}")
TAGS_REGEX = re.compile(r"[\U000E0001-\U000E007E]{4,}")


class DecodedLayer:
    def __init__(
        self,
        text: str,
        start: int,
        end: int,
        encoding: str,
        depth: int,
        raw_blob: str,
    ) -> None:
        self.text = text
        self.start = start
        self.end = end
        self.encoding = encoding
        self.depth = depth
        self.raw_blob = raw_blob


def is_printable_ratio(s: str, min_ratio: float = 0.85) -> bool:
    if not s:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\r\n\t")
    return (printable / len(s)) >= min_ratio


def normalize(text: str) -> tuple[str, list[int]]:
    """
    Normalize text per spec §4.2:
    - NFKC
    - casefold
    - drop Cf and zero-width
    - collapse whitespace to single space
    Returns (normalized_text, idx_map) where idx_map[i] is the original char offset.
    """
    norm_chars: list[str] = []
    idx_map: list[int] = []

    in_whitespace = False

    for orig_idx, c in enumerate(text):
        o = ord(c)
        if o < 128:
            if c.isspace():
                if not in_whitespace:
                    norm_chars.append(" ")
                    idx_map.append(orig_idx)
                    in_whitespace = True
            else:
                norm_chars.append(c.lower())
                idx_map.append(orig_idx)
                in_whitespace = False
        else:
            if c in ZERO_WIDTH_CHARS or unicodedata.category(c) == "Cf":
                continue
            nfkc_c = unicodedata.normalize("NFKC", c)
            folded = nfkc_c.casefold()
            for sub_c in folded:
                if sub_c.isspace():
                    if not in_whitespace:
                        norm_chars.append(" ")
                        idx_map.append(orig_idx)
                        in_whitespace = True
                else:
                    norm_chars.append(sub_c)
                    idx_map.append(orig_idx)
                    in_whitespace = False

    return "".join(norm_chars), idx_map


def strip(text: str) -> tuple[str, list[int]]:
    """
    Strip text for protected-value matching (spec §4.2):
    As normalize, then drop every non-alphanumeric character.
    Returns (stripped_text, idx_map).
    """
    stripped_chars: list[str] = []
    idx_map: list[int] = []

    for orig_idx, c in enumerate(text):
        o = ord(c)
        if o < 128:
            if c.isalnum():
                stripped_chars.append(c.lower())
                idx_map.append(orig_idx)
        else:
            if c in ZERO_WIDTH_CHARS or unicodedata.category(c) == "Cf":
                continue
            nfkc_c = unicodedata.normalize("NFKC", c)
            folded = nfkc_c.casefold()
            for sub_c in folded:
                if sub_c.isalnum():
                    stripped_chars.append(sub_c)
                    idx_map.append(orig_idx)

    return "".join(stripped_chars), idx_map


def decode_layers(text: str, max_depth: int = 2) -> list[DecodedLayer]:
    """
    Detect and decode candidate blobs up to max_depth (spec §4.2).
    Supported encodings: base64, hex, percent (url), unicode tags.
    """
    results: list[DecodedLayer] = []

    def _decode_layer_rec(current_text: str, current_depth: int, parent_enc: str, parent_start: int, parent_end: int) -> None:
        if current_depth > max_depth:
            return

        candidates: list[tuple[str, int, int, str]] = []

        # 1. Unicode tag characters
        for m in TAGS_REGEX.finditer(current_text):
            raw = m.group(0)
            ascii_chars = [chr(ord(c) - 0xE0000) for c in raw if 0x20 <= (ord(c) - 0xE0000) <= 0x7E]
            decoded = "".join(ascii_chars)
            if decoded and is_printable_ratio(decoded):
                enc = f"{parent_enc}>tags" if parent_enc else "tags"
                candidates.append((decoded, m.start(), m.end(), enc))

        # 2. Percent-encoded
        for m in PERCENT_REGEX.finditer(current_text):
            raw = m.group(0)
            try:
                decoded = urllib.parse.unquote_to_bytes(raw).decode("utf-8", errors="ignore")
                if decoded and is_printable_ratio(decoded):
                    enc = f"{parent_enc}>url" if parent_enc else "url"
                    candidates.append((decoded, m.start(), m.end(), enc))
            except Exception:
                pass

        # 3. Hex
        for m in HEX_REGEX.finditer(current_text):
            raw = m.group(0)
            try:
                decoded = bytes.fromhex(raw).decode("utf-8", errors="ignore")
                if decoded and is_printable_ratio(decoded):
                    enc = f"{parent_enc}>hex" if parent_enc else "hex"
                    candidates.append((decoded, m.start(), m.end(), enc))
            except Exception:
                pass

        # 4. Base64
        for m in BASE64_REGEX.finditer(current_text):
            raw = m.group(0)
            # Ensure valid padding
            pad_len = (4 - len(raw) % 4) % 4
            padded = raw + ("=" * pad_len)
            try:
                decoded_bytes = base64.b64decode(padded, validate=False)
                if len(decoded_bytes) <= 64 * 1024:
                    decoded = decoded_bytes.decode("utf-8", errors="ignore")
                    if decoded and is_printable_ratio(decoded):
                        enc = f"{parent_enc}>base64" if parent_enc else "base64"
                        candidates.append((decoded, m.start(), m.end(), enc))
            except Exception:
                pass

        # Limit to max 20 candidates per layer
        for dec_text, c_start, c_end, enc in candidates[:20]:
            orig_start = parent_start if current_depth > 1 else c_start
            orig_end = parent_end if current_depth > 1 else c_end
            raw_blob = current_text[c_start:c_end]

            layer = DecodedLayer(
                text=dec_text,
                start=orig_start,
                end=orig_end,
                encoding=enc,
                depth=current_depth,
                raw_blob=raw_blob,
            )
            results.append(layer)

            # Recurse if below max_depth
            if current_depth < max_depth:
                _decode_layer_rec(
                    dec_text,
                    current_depth + 1,
                    enc,
                    orig_start,
                    orig_end,
                )

    _decode_layer_rec(text, 1, "", 0, len(text))
    return results
