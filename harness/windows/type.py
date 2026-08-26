#!/usr/bin/env python3
"""Type a string into the VM through the QEMU monitor.

A fallback for bootstrapping the guest before any remoting exists: QEMU's
`sendkey` is the only input channel that needs nothing installed inside
Windows. Usage: type.sh 'text to type'  [--enter]
"""
import os
import subprocess
import sys
import time

SOCK = "unix-connect:" + os.path.expanduser(
    os.environ.get("KMSRSOS_VM_DIR", "~/vm/win11")) + "/monitor.sock"

# Unshifted US-layout keys whose qemu name is not just the character.
NAMED = {
    " ": "spc", "\t": "tab", "\n": "ret", "-": "minus", "=": "equal",
    "[": "bracket_left", "]": "bracket_right", ";": "semicolon",
    "'": "apostrophe", "\\": "backslash", ",": "comma", ".": "dot",
    "/": "slash", "`": "grave_accent",
}
# Characters reached with shift, mapped to the key that produces them.
SHIFTED = {
    "!": "1", "@": "2", "#": "3", "$": "4", "%": "5", "^": "6", "&": "7",
    "*": "8", "(": "9", ")": "0", "_": "minus", "+": "equal",
    "{": "bracket_left", "}": "bracket_right", ":": "semicolon",
    '"': "apostrophe", "|": "backslash", "<": "comma", ">": "dot",
    "?": "slash", "~": "grave_accent",
}


def keys_for(ch):
    if ch in NAMED:
        return NAMED[ch]
    if ch in SHIFTED:
        return f"shift-{SHIFTED[ch]}"
    if ch.isdigit() or (ch.isalpha() and ch.islower()):
        return ch
    if ch.isalpha() and ch.isupper():
        return f"shift-{ch.lower()}"
    raise ValueError(f"no key mapping for {ch!r}")


def send(lines):
    payload = "".join(f"{line}\n" for line in lines)
    subprocess.run(["socat", "-", SOCK], input=payload.encode(),
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                   timeout=120)


def main():
    args = [a for a in sys.argv[1:]]
    enter = "--enter" in args
    if enter:
        args.remove("--enter")
    text = " ".join(args)

    # Chunked so a long line does not overrun the monitor's input buffer.
    batch, count = [], 0
    for ch in text:
        batch.append(f"sendkey {keys_for(ch)}")
        count += 1
        if len(batch) >= 24:
            send(batch)
            batch = []
            time.sleep(0.12)
    if batch:
        send(batch)
    if enter:
        time.sleep(0.15)
        send(["sendkey ret"])
    print(f"typed {count} chars{' + enter' if enter else ''}")


if __name__ == "__main__":
    main()
