# Bidi-override fixture — wraps a comment in U+202E (RLO) so a human reading
# the source sees one string but the parser executes another. This is the
# Trojan Source pattern (CVE-2021-42574).
# ‮ this text is logically reversed ‬
access = "granted"
