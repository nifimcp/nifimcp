"""Source-linked operator notes (optional bundle data).

A note is an operator assertion bound to a source hash and JSON pointer. It is
current only while the exact source bytes it was written against are loaded and
its pointer still resolves. Notes never override NiFi evidence and are never
authentication or authorization for anything.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from ..util import parse_iso
from . import pointer as jp
from .evidence import EvidenceSet, make_evidence, make_finding
from .redact import Redactor


class Note(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    note_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
    author: str = Field(min_length=1, max_length=200)
    created_at: str
    source_file: str = Field(max_length=128)
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    pointer: str = Field(max_length=4096)
    component_id: str | None = Field(default=None, max_length=128)
    text: str = Field(min_length=1, max_length=4000)
    origin: str = Field(pattern=r"^(operator_note|human_transcribed)$")


class NotesFile(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    notes_schema: str = Field(pattern=r"^nifimcp-notes/1$")
    notes: list[Note] = Field(max_length=1000)


def note_status(note: Note, sources: dict[str, tuple[str, Any]]) -> str:
    """sources: filename -> (sha256, document). Returns current | stale_source | missing_reference | source_unavailable."""
    current = sources.get(note.source_file)
    if current is None:
        return "source_unavailable"
    sha, document = current
    if sha != note.source_sha256:
        return "stale_source"
    try:
        jp.resolve(document, note.pointer)
    except jp.PointerError:
        return "missing_reference"
    return "current"


def apply_notes(doc: Any, *, notes_source_id: str, notes_hash: str, notes_pointer_base: str,
                sources: dict[str, tuple[str, Any]], collected_at: str, redactor: Redactor,
                out: EvidenceSet) -> dict:
    try:
        parsed = NotesFile.model_validate(doc)
    except ValidationError:
        out.add_gap("NOTES_REJECTED", "The operator notes file failed validation and was ignored.")
        return {"current": 0, "stale": 0}
    counts = {"current": 0, "stale": 0}
    for i, note in enumerate(parsed.notes):
        try:
            parse_iso(note.created_at)
        except ValueError:
            out.add_gap("NOTE_REJECTED", f"Note {note.note_id} has an invalid timestamp and was ignored.")
            continue
        status = note_status(note, sources)
        facts = {"note_id": note.note_id, "author": redactor.name(note.author), "origin": note.origin,
                 "status": status, "text": redactor.bulletin_message(note.text), "bound_source_file": note.source_file,
                 "bound_source_sha256": note.source_sha256, "bound_pointer": note.pointer, "untrusted_text": True}
        ev = out.add_evidence(make_evidence(kind="operator_note", source_id=notes_source_id, source_hash=notes_hash,
                                            source_pointer=jp.join(notes_pointer_base, "notes", i), facts=facts,
                                            collected_at=collected_at, component_id=note.component_id,
                                            event_time=note.created_at))
        if status == "current":
            counts["current"] += 1
            label = "Human-transcribed assertion" if note.origin == "human_transcribed" else "Operator note"
            out.add_finding(make_finding(
                finding_id=f"NOTE:{note.note_id}", kind="operator_assertion", severity="info", evidence_ids=[ev],
                statement=f"{label} by {facts['author']} on component {note.component_id}: {facts['text']}",
                limitations=["Operator assertion; not machine-collected NiFi evidence and cannot override it.",
                             "Bound to the exact source bytes cited; any source change makes it stale.",
                             "Never authorization for any operation."]))
        else:
            counts["stale"] += 1
            out.add_gap("STALE_NOTE",
                        f"Note {note.note_id} is {status.replace('_', ' ')} and was not used as current context.")
    return counts
