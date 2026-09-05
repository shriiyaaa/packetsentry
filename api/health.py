"""Explicit Vercel function entrypoint for the health route."""

from .index import app

__all__ = ["app"]
