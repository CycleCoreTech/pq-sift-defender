"""Tool schemas exposed to the agent (OpenAI/Ollama function-calling format)."""

from __future__ import annotations

from typing import Any

SIFT_CLASSIFY_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "sift_classify",
        "description": (
            "Classify a piece of evidence text against the security gates "
            "(SQL injection, command injection, path traversal, SSRF). "
            "Returns recommendation PASS/FLAG/BLOCK with per-gate confidence."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "text": {
                    "type": "string",
                    "description": "The evidence text to classify.",
                }
            },
            "required": ["text"],
        },
    },
}

VOL_PSLIST_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "vol_pslist",
        "description": (
            "List processes from a Windows memory image using Volatility 3 "
            "(windows.pslist plugin). Returns a list of process records with PID, "
            "PPID, ImageFileName, and timing fields."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "image_path": {
                    "type": "string",
                    "description": "Filesystem path to the memory dump file.",
                }
            },
            "required": ["image_path"],
        },
    },
}

VOL_NETSCAN_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "vol_netscan",
        "description": (
            "Scan network connections from a Windows memory image using "
            "Volatility 3 (windows.netscan plugin). Returns active and recently "
            "closed connection records."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "image_path": {
                    "type": "string",
                    "description": "Filesystem path to the memory dump file.",
                }
            },
            "required": ["image_path"],
        },
    },
}

CLAMAV_SCAN_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "clamav_scan",
        "description": (
            "Scan a file or directory with the ClamAV antivirus engine. "
            "Returns infected_count, list of detected signatures, and scan stats."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_path": {
                    "type": "string",
                    "description": "Filesystem path to file or directory to scan.",
                }
            },
            "required": ["target_path"],
        },
    },
}

TSK_MMLS_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "tsk_mmls",
        "description": (
            "List partitions in a disk image using The Sleuth Kit (mmls). "
            "Returns partition table with start sectors, lengths, and descriptions."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "image_path": {
                    "type": "string",
                    "description": "Filesystem path to the raw disk image.",
                }
            },
            "required": ["image_path"],
        },
    },
}

TSK_FLS_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "tsk_fls",
        "description": (
            "List files in a filesystem image (including deleted entries) using "
            "The Sleuth Kit (fls). Returns directory entries with inode numbers "
            "and is_deleted flags."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "image_path": {
                    "type": "string",
                    "description": "Filesystem path to the raw disk image.",
                },
                "offset": {
                    "type": "integer",
                    "description": "Sector offset to the partition (default 0).",
                    "default": 0,
                },
            },
            "required": ["image_path"],
        },
    },
}

PLASO_TIMELINE_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "plaso_timeline",
        "description": (
            "Build a forensic super-timeline from logs, disk images, or "
            "filesystem evidence using Plaso (log2timeline + psort). Returns "
            "a chronological list of parsed events with source and message."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "target_path": {
                    "type": "string",
                    "description": "Filesystem path to the evidence to analyze.",
                },
                "parsers": {
                    "type": "string",
                    "description": "Plaso parser filter (e.g. 'syslog,winevtx').",
                },
                "max_events": {
                    "type": "integer",
                    "description": "Cap on number of events returned (default 100).",
                    "default": 100,
                },
            },
            "required": ["target_path"],
        },
    },
}

YARA_MATCH_TOOL: dict[str, Any] = {
    "type": "function",
    "function": {
        "name": "yara_match",
        "description": (
            "Compile a YARA rule and match it against a text or file path. "
            "Use to test custom signature patterns against suspicious indicators "
            "(strings, paths, evidence text). Returns matched rules and metadata."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "rule_source": {
                    "type": "string",
                    "description": "YARA rule source text.",
                },
                "target_text": {
                    "type": "string",
                    "description": "Text to scan (alternative to file_path).",
                },
                "file_path": {
                    "type": "string",
                    "description": "Filesystem path to scan (alternative to target_text).",
                },
            },
            "required": ["rule_source"],
        },
    },
}

ALL_TOOLS_OPENAI_FORMAT: list[dict[str, Any]] = [
    SIFT_CLASSIFY_TOOL,
    VOL_PSLIST_TOOL,
    VOL_NETSCAN_TOOL,
    CLAMAV_SCAN_TOOL,
    TSK_MMLS_TOOL,
    TSK_FLS_TOOL,
    PLASO_TIMELINE_TOOL,
    YARA_MATCH_TOOL,
]
