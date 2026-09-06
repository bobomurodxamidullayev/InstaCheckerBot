"""
middlewares/__init__.py — Middlewares paketi eksporti.
"""

from middlewares.auth import AdminOnlyMiddleware

__all__ = ["AdminOnlyMiddleware"]
