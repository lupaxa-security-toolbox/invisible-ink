"""Typed failures and stable process exit codes."""

from __future__ import annotations


class InkError(Exception):
    """Base error carrying a stable code and process exit status."""

    code = "operation_failed"
    exit_code = 1

    def __init__(self, message: str) -> None:
        super().__init__(message)


class ArgumentError(InkError):
    """Invalid arguments or configuration."""

    code = "invalid_arguments"
    exit_code = 2


class UnsupportedError(InkError):
    """Unsupported method, format, or placement."""

    code = "unsupported"
    exit_code = 3


class CapacityError(InkError):
    """The cover cannot hold the payload."""

    code = "insufficient_capacity"
    exit_code = 4


class NotFoundError(InkError):
    """No recognised framed message was found."""

    code = "not_found"
    exit_code = 5


class IntegrityError(InkError):
    """The encoded message is truncated or corrupted."""

    code = "integrity_failure"
    exit_code = 6


class AuthenticationError(InkError):
    """Password, key, or authentication tag failure."""

    code = "authentication_failed"
    exit_code = 7


class FilesystemError(InkError):
    """Permission, path, or output-collision failure."""

    code = "filesystem_error"
    exit_code = 8


class VerificationError(InkError):
    """A recovered payload did not match the expected message."""

    code = "verification_failed"
    exit_code = 9


class LimitError(InkError):
    """A configured safety limit was exceeded."""

    code = "limit_exceeded"
    exit_code = 10
