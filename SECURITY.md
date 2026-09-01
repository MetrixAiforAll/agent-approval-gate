# Security

This is a demonstration repository. There is no production deployment, hosted service or
published package to report issues against.

The threat model and its deliberate limits are in the README's **Non-goals** section. If you
find a way to make `send_email` execute without an `internal_untainted` verdict or a human
approval token — a non-zero breach rate — that is a P0 defect in the demonstration itself:
please open a GitHub issue with the minimal tool call that does it, using only RFC 2606
example domains.
