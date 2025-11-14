# app/storage/transcript.py
# "Append-only transcript + TranscriptHash helpers."

import os
import json
import hashlib
from datetime import datetime, timezone

# --------------------------------------------------------------------
# Each chat session has its own file, e.g.:
#   transcripts/<session_id>.json
# This keeps all users’ transcripts separated and makes hashing easier.

TRANSCRIPT_DIR = "transcripts"

# Create the folder if it doesn't exist (first run).
if not os.path.exists(TRANSCRIPT_DIR):
    os.makedirs(TRANSCRIPT_DIR)
# --------------------------------------------------------------------


# --------------------------------------------------------------------
# INTERNAL HELPER: Build the full filesystem path to the transcript file.
# Given session_id="abc123", it returns:
#   "transcripts/abc123.json"
# This function keeps path-building consistent everywhere.
# --------------------------------------------------------------------
def _session_path(session_id: str) -> str:
    """Return path to transcript file for this session."""
    return os.path.join(TRANSCRIPT_DIR, f"{session_id}.json")
# --------------------------------------------------------------------


# --------------------------------------------------------------------
# adds one new message to the append-only transcript.
#
# Every message that passes through the server must be stored here
# to enable non-repudiation + integrity checking.
#
# Format of each entry:
#   {
#       "timestamp": <ms since epoch>,
#       "sender": "alice" or "bob",
#       "ciphertext": "<base64 encrypted message>",
#       "signature": "<signature of ciphertext>"
#   }
#
# The transcript file is simply a list of these entries in JSON.
# --------------------------------------------------------------------
def append_message(session_id: str, sender: str, ciphertext_b64: str, signature_b64: str):
    
    # Full path to "<session>.json"
    path = _session_path(session_id)

    # Loads existing transcript, OR create empty list.
    # This lets us append without losing older messages.
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            transcript = json.load(f)     # Load list of entries
    else:
        transcript = []                   # First message in this chat


    # Build a NEW transcript entry.
    # timestamp is in milliseconds (using timezone-aware UTC).
    entry = {
        "timestamp": int(datetime.now(timezone.utc).timestamp() * 1000),
        "sender": sender,
        "ciphertext": ciphertext_b64,
        "signature": signature_b64,
    }

    # Add entry to the list (append-only)
    transcript.append(entry)

    # Write back updated transcript to the JSON file (pretty-printed with indentation).
    with open(path, "w", encoding="utf-8") as f:
        json.dump(transcript, f, indent=2)
# --------------------------------------------------------------------

# --------------------------------------------------------------------
# compute_transcript_hash()
# for non-repudiation.**
#
# After the session ends, you compute this hash and return it to BOTH
# users in a signed "Receipt". If someone modifies the transcript,
# the hash WILL change.
#
# Hashing strategy:
# Concatenate:
#   timestamp + sender + ciphertext + signature
#
# For ALL messages, in order.
#
# Then compute:
#   SHA256(concatenated_string)
#
# This gives a **single 64-char hex digest** that uniquely represents
# the entire transcript.
# --------------------------------------------------------------------
def compute_transcript_hash(session_id: str) -> str:
    
   # Computes the SHA-256 hash of the transcript.
   # Concatenation format:
    #    timestamp + sender + ciphertext + signature

    path = _session_path(session_id)

    # If no transcript exists (session had no messages), return empty string.
    if not os.path.exists(path):
        return ""

    # Load full transcript (list of message entries)
    with open(path, "r", encoding="utf-8") as f:
        transcript = json.load(f)


    # Build a single long string containing all fields in deterministic order.
    concat = ""
    for e in transcript:
        concat += f"{e['timestamp']}{e['sender']}{e['ciphertext']}{e['signature']}"

    # Return SHA-256 hex digest
    return hashlib.sha256(concat.encode("utf-8")).hexdigest()


# --------------------------------------------------------------------
# --------------------------------------------------------------------
# MANUAL DRIVER TEST (run this file directly to test)
#
# It will write 3 messages into "transcripts/demo_session.json"
# and print the resulting transcript hash.
if __name__ == "__main__":
    session = "demo_session"

    print("[+] Appending messages...")
    append_message(session, "alice", "ciphertext123", "sigAlice")
    append_message(session, "bob", "ciphertext456", "sigBob")
    append_message(session, "alice", "ciphertext789", "sig3")

    print("[+] Transcript hash =", compute_transcript_hash(session))
    print("\nOpen transcripts/demo_session.json to verify append-only behavior.")
# --------------------------------------------------------------------
# --------------------------------------------------------------------
#cli commands to run the test:
#   python app/storage/transcript.py