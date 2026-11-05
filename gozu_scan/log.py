"""GitHub Actions log commands."""

from __future__ import annotations


def warning(message: str) -> None:
    print(f"::warning::{message}", flush=True)


def notice(message: str) -> None:
    print(f"::notice::{message}", flush=True)


def error(message: str) -> None:
    print(f"::error::{message}", flush=True)
