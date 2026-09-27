"""Signatures shared by the file-disclosure detectors.

Both path traversal / LFI (``traversal.py``) and XXE file read (``xxe.py``)
confirm success the same way: the response contains the contents of a well-known
file. Compiled once and reused so the two modules stay in lock-step.
"""
import re

# /etc/passwd line format, plus Windows win.ini / boot.ini section markers.
FILE_DISCLOSURE = re.compile(
    r"root:.*:0:0:"                 # /etc/passwd
    r"|\[boot loader\]"             # boot.ini
    r"|\[fonts\]|\[extensions\]"    # win.ini
    r"|for 16-bit app support",     # win.ini
    re.I,
)
