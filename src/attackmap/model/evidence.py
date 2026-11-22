"""Redaction base for evidence-carrying models (#235, #14)."""


from __future__ import annotations

from pydantic import BaseModel, Field, model_validator

from attackmap.foundation.redact import redact_list, redact_text

# Provenance field. Present on every analyzer-emitted signal so downstream
# consumers can trace a signal back to the analyzer that produced it.
# Excluded from serialization by default (see #14) so JSON/CLI reports are
# byte-for-byte unchanged; access it via Python attribute for debugging,
# confidence scoring, or future finder logic.
_PROVENANCE_FIELD = Field(default=None, exclude=True, repr=False)


# Fields that carry text copied out of the scanned repository. Every model
# with one of these redacts it at construction time (#235), so no detector —
# core or plugin — can put a raw credential into a report, SARIF, PR comment
# or LLM pack.
_EVIDENCE_TEXT_FIELDS = ("evidence_text", "db_evidence", "sanitizer_evidence", "target")
_EVIDENCE_LIST_FIELDS = ("evidence",)


class _RedactedEvidence(BaseModel):
    @model_validator(mode="after")
    def _redact_evidence(self):  # type: ignore[no-untyped-def]
        fields = type(self).model_fields
        for name in _EVIDENCE_TEXT_FIELDS:
            if name in fields:
                value = getattr(self, name)
                if isinstance(value, str):
                    redacted = redact_text(value)
                    if redacted != value:
                        object.__setattr__(self, name, redacted)
        for name in _EVIDENCE_LIST_FIELDS:
            if name in fields:
                value = getattr(self, name)
                if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
                    redacted_list = redact_list(value)
                    if redacted_list != value:
                        object.__setattr__(self, name, redacted_list)
        return self
