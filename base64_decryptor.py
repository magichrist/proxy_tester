"""Base64 subscription decoding.

Subscription endpoints frequently serve their whole list base64-encoded, and
just as frequently wrapped at 64 or 76 characters by whatever produced them.
The previous implementation only decoded a line when the *whole* line matched
``[A-Za-z0-9+/=]+``, so a wrapped payload was never recognised: its fragments are
individually not valid base64 and the run silently produced an identical copy.

The decoder therefore works on maximal runs of consecutive base64-*candidate*
lines: each run is joined, decoded, and the decoded text is re-split into
lines. Anything that does not decode to plausible text is passed through
untouched, so a plain link file is never mangled.

Both the standard and the URL-safe alphabets are accepted, by the guards and
by the decoder alike, because subscription servers emit either.

Public API kept stable for existing call sites::

    runner(input_file, output_file) -> DecodeStats
    is_base64(s) -> bool
"""

from __future__ import annotations

import base64
import binascii
import re
import string
from dataclasses import dataclass

__all__ = ["DecodeStats", "is_base64", "runner"]

#: Minimum payload length worth attempting; below this a "decode" is noise.
#: Also the shortest joined body :func:`_decode_lines` will even try to decode,
#: so a stray 4-character fragment cannot be decoded into plausible-looking junk.
MIN_PAYLOAD_LEN = 8
#: How many trailing lines of a candidate run may be trimmed off while hunting
#: for a decodable body. See :func:`_decode_lines` for why the bound exists.
MAX_TRIM_LINES = 64

#: The two RFC 4648 alphabets. ``_decode_body`` translates ``-_`` to ``+/``
#: before decoding, so a body in *either* alphabet is decodable -- and the
#: guards have to agree with that, or a URL-safe payload decodes fine and is
#: then refused by the very gate that is supposed to let it through.
_B64_STANDARD = frozenset(string.ascii_letters + string.digits + "+/")
_B64_URLSAFE = frozenset(string.ascii_letters + string.digits + "-_")
#: Every character a base64 *candidate* line may contain: both alphabets plus
#: the padding character. Deliberately an over-approximation -- see
#: :func:`_looks_like_base64` for why being permissive here is the safe side to
#: err on, and :func:`_decode_lines` for where the real decision is made.
_B64_CHARS = _B64_STANDARD | _B64_URLSAFE | {"="}
_URLSAFE_TO_STD = str.maketrans("-_", "+/")
_WHITESPACE = re.compile(r"\s+")
#: Control characters that may not appear in decoded output. Tab, LF and CR are
#: excluded from the set because a link list legitimately contains them.
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass(frozen=True, slots=True)
class DecodeStats:
    """Accounting for one decode pass, so a caller can report what happened.

    ``b64_blocks`` counts the maximal spans of base64-looking lines the scanner
    found, and ``decoded_blocks`` how many of those actually turned out to be a
    payload; the difference is prose that merely looked like base64.
    """

    lines_in: int
    lines_out: int
    b64_blocks: int
    decoded_blocks: int
    decoded_lines: int
    passthrough_lines: int

    @property
    def decoded(self) -> bool:
        """True when at least one base64 block was decoded in this pass."""
        return self.decoded_blocks > 0


def _strip_whitespace(text: str) -> str:
    """Remove every whitespace character, so wrapped payloads join cleanly."""
    return _WHITESPACE.sub("", text)


def _plausible_text(text: str) -> bool:
    """True when decoded bytes look like link-list text rather than binary noise.

    Requiring a colon rejects a run of digits that merely happens to be
    valid base64; rejecting control characters rejects binary payloads that
    happened to decode as valid UTF-8. The control-character test is a single
    regex search rather than a per-character loop, because it runs over every
    decoded megabyte of a large subscription file.
    """
    if ":" not in text:
        return False
    return _CONTROL.search(text) is None


def _decode_body(body: str) -> str | None:
    """Decode one joined base64 body to text, or None when it is not base64.

    Accepts both the standard and URL-safe alphabets, and tolerates missing
    padding. Never raises.
    """
    if not body:
        return None
    candidates = [body]
    translated = body.translate(_URLSAFE_TO_STD)
    if translated != body:
        candidates.append(translated)
    for candidate in candidates:
        padded = candidate + "=" * (-len(candidate) % 4)
        try:
            raw = base64.b64decode(padded, validate=True)
        except (binascii.Error, ValueError):
            continue
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if _plausible_text(text):
            return text
    return None


def is_base64(s: str) -> bool:
    """Return True when ``s`` is a base64 payload that decodes to plausible text.

    Internal whitespace is ignored, so a payload wrapped across lines can be
    tested as a single string. Both the standard and the URL-safe alphabet are
    accepted, matching :func:`_decode_body`; a guard that disagreed with the
    decoder would refuse payloads the decoder is perfectly able to read. Used
    as a cheap guard; :func:`runner` does its own detection so it never depends
    on callers honouring this.
    """
    if not isinstance(s, str):
        return False
    body = _strip_whitespace(s)
    if len(body) < MIN_PAYLOAD_LEN:
        return False
    if not set(body) <= _B64_CHARS:
        return False
    return _decode_body(body) is not None


def _looks_like_base64(line: str) -> bool:
    """True when ``line`` could be a *fragment* of a base64 payload.

    This is a candidate test, not a decision. It asks only two questions: is
    anything left after whitespace is stripped, and is every remaining
    character in :data:`_B64_CHARS` (both alphabets, plus ``=``)?

    Why so permissive, given that alphabet membership alone cannot tell a
    payload from an English sentence? Stripping whitespace turns
    ``"plain trailing line"`` into ``"plaintrailingline"``, which is nothing
    but base64 letters -- so *any* membership rule lets prose qualify. The
    tempting fix, a per-line minimum length, does not work either: the tail of a
    wrapped payload is ``len(blob) % width`` characters, so across the widths a
    real feed actually uses, and across the arbitrary ones, a 4-character floor
    rejects genuine 1-3 character fragments -- and would still not separate a
    4-character payload fragment from a 4-character English word. Length alone
    is not a discriminator.

    So this function deliberately errs toward false positives and
    :func:`_decode_lines` resolves them, by requiring the *joined run* to
    decode to plausible text and trimming the run back until it does. The
    asymmetry is what makes the choice safe: a line wrongly admitted as a
    candidate costs one extra decode attempt and is then emitted verbatim,
    whereas a line wrongly rejected truncates the run and can cost the payload
    the whole run -- which is the silent data-loss failure this replaces.
    """
    body = _strip_whitespace(line)
    if not body:
        return False
    return not (set(body) - _B64_CHARS)


def _decode_lines(lines: list[str]) -> tuple[list[str], int, int, int]:
    """Expand base64 runs in ``lines``; return (out_lines, blocks, decoded, decoded_lines).

    A span is the maximal run of consecutive :func:`_looks_like_base64` lines.
    It is decoded longest-first, and each time that fails its last line is
    trimmed off and the shorter run retried, up to :data:`MAX_TRIM_LINES` times
    *for the whole span*. That backtracking is what keeps trailing prose, a
    trailing comment, or a stray padding character from poisoning the payload
    in front of it: the full span does not decode, the span without the
    offender does, so the payload is recovered and the offending line is then
    re-examined on its own and passed through verbatim.

    When a span cannot be decoded even at one line, that single line is emitted
    and the next line is tried as a fresh run, because it may be the real start
    of a payload -- a sentence sitting between two blocks, say.

    The trim budget is per span, not per line, and the whole span is consumed by
    one pass. Both matter for cost: a file can be megabytes of base64-looking
    text that is *not* a payload (an embedded certificate, a base64 image), and
    re-deriving the span end and re-running the trim loop after every single
    line would make that quadratic. With the budget spent, the remainder of the
    span is passed through wholesale, exactly as an undecodable file always was.
    """
    out: list[str] = []
    blocks = 0
    decoded_blocks = 0
    decoded_lines = 0
    index = 0
    total = len(lines)

    while index < total:
        if not _looks_like_base64(lines[index]):
            out.append(lines[index])
            index += 1
            continue

        end = index
        while end < total and _looks_like_base64(lines[end]):
            end += 1
        blocks += 1

        # Stripped once; trimming must not re-strip the lines it keeps. ``start``
        # anchors the slice offsets, because ``index`` advances inside the loop
        # and these offsets are relative to where the span began.
        start = index
        pieces = [_strip_whitespace(line) for line in lines[start:end]]
        trims_left = MAX_TRIM_LINES
        while index < end:
            run_end = end
            decoded: str | None = None
            while True:
                body = "".join(pieces[index - start : run_end - start])
                if len(body) >= MIN_PAYLOAD_LEN:
                    decoded = _decode_body(body)
                if decoded is not None or run_end - index <= 1 or trims_left <= 0:
                    break
                run_end -= 1
                trims_left -= 1

            if decoded is None:
                out.append(lines[index])
                index += 1
                if trims_left <= 0:
                    # Budget gone: the rest of this span is not a payload, and
                    # re-attempting it per line would be quadratic on a large
                    # base64-looking file. Hand it over untouched.
                    out.extend(lines[index:end])
                    index = end
                continue

            expanded = decoded.splitlines()
            out.extend(expanded)
            decoded_blocks += 1
            decoded_lines += len(expanded)
            index = run_end

    return out, blocks, decoded_blocks, decoded_lines


def runner(input_file, output_file) -> DecodeStats:
    """Decode ``input_file`` into ``output_file``, passing plain lines through.

    The whole file is read once, base64 runs are decoded, and the result is
    written with LF endings. Returns a :class:`DecodeStats` describing the pass;
    ``decoded`` is False for a file that was already plain text, which lets the
    caller report "nothing was encoded here" instead of implying a decode.
    """
    with open(input_file, "r", encoding="utf-8", errors="replace") as handle:
        raw = handle.read()

    lines_in = raw.splitlines()
    out_lines, blocks, decoded_blocks, decoded_lines = _decode_lines(lines_in)

    with open(output_file, "w", encoding="utf-8", newline="\n") as handle:
        handle.writelines(line + "\n" for line in out_lines)

    return DecodeStats(
        lines_in=len(lines_in),
        lines_out=len(out_lines),
        b64_blocks=blocks,
        decoded_blocks=decoded_blocks,
        decoded_lines=decoded_lines,
        passthrough_lines=len(lines_in) - decoded_lines,
    )
