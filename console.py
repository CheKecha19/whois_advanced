"""Compact terminal progress; redirected output stays free of animation."""

import shutil
import sys
import time


class Progress:
    def __init__(self, total, quiet=False, verbose=False):
        self.total = total
        self.quiet = quiet
        self.verbose = verbose
        self.tty = sys.stderr.isatty() and not quiet and not verbose
        self.started = time.monotonic()
        self.last_draw = 0
        self.done = self.successful = self.cached = self.resumed = 0

    def update(self, result):
        self.done += 1
        self.successful += result["success"] == "Yes"
        self.cached += bool(result["cache_hit"])
        self.resumed += bool(result["resumed"])
        if self.quiet:
            return
        if self.verbose:
            print(f"[{self.done}/{self.total}] {result['ip']}: {result['completeness']} ({result['data_source']})", file=sys.stderr)
            if result["error_message"]:
                print(result["error_message"], file=sys.stderr)
        elif self.tty:
            now = time.monotonic()
            if now - self.last_draw < 0.1 and self.done != self.total:
                return
            self.last_draw = now
            elapsed = now - self.started
            eta = elapsed / self.done * (self.total - self.done)
            text = (f"{self.done}/{self.total} ({self.done / self.total:.0%}) | "
                    f"OK {self.successful} | кэш {self.cached} | продолжено {self.resumed} | ETA ~{eta:.0f} с")
            width = max(10, shutil.get_terminal_size((100, 24)).columns - 1)
            print("\r\033[2K" + text[:width], end="", file=sys.stderr, flush=True)

    def close(self):
        if self.tty and self.done:
            print(file=sys.stderr)
