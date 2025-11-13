#"""Append-only transcript + TranscriptHash helpers.""" 
#raise NotImplementedError("students: implement transcript layer")

"""Append-only transcript + TranscriptHash helpers."""
import os
import json
import hashlib
from datetime import datetime

TRANSCRIPT_DIR = "transcripts"

if not os.path.exists(TRANSCRIPT_DIR):
    os.makedirs(TRANSCRIPT_DIR)


def append_message(session_id: str, sender: str, ciphertext_b64: str, signature_b64: str):
    """Append a message to the transcript for a session."""
    session_file = os.path.join(TRANSCRIPT_DIR, f"{session_id}.json")
    entry = {
        "timestamp": int(datetime.utcnow().timestamp() * 1000),
        "sender": sender,
        "ciphertext": ciphertext_b64,
        "signature": signature_b64,
    }

    transcript = []
    if os.path.exists(session_file):
        with open(session_file, "r", encoding="utf-8") as f:
            transcript = json.load(f)

    transcript.append(entry)

    with open(session_file, "w", encoding="utf-8") as f:
        json.dump(transcript, f, indent=2)


def compute_transcript_hash(session_id: str) -> str:
    """Return SHA-256 hash of concatenated transcript entries (hex)."""
    session_file = os.path.join(TRANSCRIPT_DIR, f"{session_id}.json")
    if not os.path.exists(session_file):
        return ""

    with open(session_file, "r", encoding="utf-8") as f:
        transcript = json.load(f)

    concatenated = "".join(
        f"{e['timestamp']}{e['sender']}{e['ciphertext']}{e['signature']}" for e in transcript
    ).encode("utf-8")

    return hashlib.sha256(concatenated).hexdigest()


# ----------------------
# Driver/test code
# ----------------------
if __name__ == "__main__":
    session = "test_session"
    append_message(session, "alice", "ciphertext123", "sig123")
    append_message(session, "bob", "ciphertext456", "sig456")
    print("Transcript hash:", compute_transcript_hash(session))

