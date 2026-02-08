from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flask import Flask


def create_app() -> "Flask":
    from .app import create_app as _create_app

    return _create_app()


__all__ = ["create_app"]
