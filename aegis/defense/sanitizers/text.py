import unicodedata
import regex

class InputSanitizer:
    """
    Deterministic sanitizer engineered to neutralize invisible Unicode smuggling,
    zero-width characters, homoglyphs, and known prompt injection patterns[cite: 22].
    """

    INVISIBLE_CHARS = regex.compile(
        r"[\u200B-\u200D\uFEFF\u200E\u200F\u202A-\u202E\U000E0000-\U000E007F]"
    )

    INJECTION_PATTERNS = [
        regex.compile(r"(?i)\bignore\s+(all\s+)?(prior|previous)\s+instructions\b"),
        regex.compile(r"(?i)\b(system\s+prompt|role\s*:\s*system)\b"),
        regex.compile(r"(?i)\b(override|disregard)\s+(all\s+)?(constraints|rules|safeguards)\b"),
        regex.compile(r"(?i)\bDAN\s*(mode|version)?\b"),
        regex.compile(r"(?i)\byou\s+(are\s+now|must|have\s+to)\s+(act\s+as|pretend|override)\b")
    ]

    @classmethod
    def canonicalize(cls, text: str) -> str:
        """Strips invisible characters, removes HTML comments, and applies NFKC normalization[cite: 22]."""
        if not text:
            return ""
        cleaned = regex.sub(r"<!--.*?-->", "", text, flags=regex.DOTALL)
        normalized = unicodedata.normalize("NFKC", cleaned)
        stripped = cls.INVISIBLE_CHARS.sub("", normalized)
        sanitized = "".join(ch for ch in stripped if ord(ch) >= 32 or ch in "\n\r\t")
        return sanitized.strip()

    @classmethod
    def scan_heuristics(cls, text: str) -> list[str]:
        """Detect known structural override patterns[cite: 22]."""
        normalized = cls.canonicalize(text)
        matches = []
        for pattern in cls.INJECTION_PATTERNS:
            if pattern.search(normalized):
                matches.append(pattern.pattern)
        return matches
