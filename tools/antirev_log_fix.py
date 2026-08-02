#!/usr/bin/env python3
"""
antirev_log_fix - restore the logging ``module``/``filename``/``pathname`` fields
under PyArmor obfuscation.

Problem
-------
PyArmor compiles obfuscated modules with a code-object ``co_filename`` of
``<frozen dotted.module.name>`` instead of the real path (even under basic
obfuscation).  The stdlib ``logging`` module fills ``LogRecord.pathname`` from
the caller frame's ``co_filename`` and derives ``filename``/``module`` from it,
so a log format using ``%(module)s`` / ``{module}`` (or ``filename``/
``pathname``) prints ``<frozen ...>`` — and, worse, ``logging``'s
``os.path.splitext`` mangles nested names (``<frozen pkg.mod>`` -> module
``<frozen pkg``).  ``__file__`` itself is UNAFFECTED; only ``co_filename`` is.

Fix
---
Install a ``LogRecordFactory`` that rewrites ``module`` from a reliable source
in BOTH modes, so the SAME dotted name prints obfuscated or not:

  * obfuscated: ``record.pathname`` is ``<frozen pkg.sub.mod>`` — strip the
    ``<frozen `` / ``>`` wrapper to get ``pkg.sub.mod`` verbatim (PyArmor embeds
    the real dotted fullname there).
  * plaintext:  ``record.pathname`` is a real path — derive the same dotted name
    the way importlib does (relative to the longest matching ``sys.path`` root).

This deliberately keys off ``co_filename``/path, NOT the logger ``name``, so it
works regardless of what you pass to ``getLogger()`` (a fixed script name, an
app name, ``__name__`` — all fine) and needs NO changes to business or
third-party code.  Keep your existing ``{module}`` format field and any log
parser/regex exactly as they are.

Usage
-----
Import once from your startup/bootstrap path, before business logging happens::

    import antirev_log_fix          # auto-installs on import

or install explicitly, optionally scoping the rewrite to your own packages so
third-party/stdlib log lines keep their default (basename) module field::

    import antirev_log_fix
    antirev_log_fix.install(only_packages=("wtmat",))

If your custom Logger subclass overrides ``makeRecord`` and bypasses the record
factory, use the ``Filter`` instead (referenceable from a dictConfig
``filters:`` section)::

    "filters": {"defrost": {"()": "antirev_log_fix.DefrostFilter"}},
    "handlers": {"console": {"class": "logging.StreamHandler",
                             "filters": ["defrost"], ...}}
"""
from __future__ import annotations

import logging
import os
import sys

_FROZEN_PREFIX = "<frozen "

# Set once, on first install, so repeated imports/installs don't stack factories.
_ORIGINAL_FACTORY = None
_INSTALLED = False


def _path_to_dotted(path: str) -> str:
    """Convert a real file path to a dotted module name, the way importlib does:
    relative to the longest ``sys.path`` entry that contains it."""
    ap = os.path.abspath(path)
    best = ""
    for root in sys.path:
        try:
            rp = os.path.abspath(root)
        except Exception:
            continue
        if os.path.isdir(rp) and (ap == rp or ap.startswith(rp + os.sep)) \
                and len(rp) > len(best):
            best = rp
    rel = ap[len(best):].lstrip(os.sep + "/") if best else os.path.basename(ap)
    return os.path.splitext(rel)[0].replace(os.sep, ".").replace("/", ".")


def defrost_module(pathname: str) -> str:
    """Return the real dotted module name for a LogRecord ``pathname``, whether
    it's a PyArmor ``<frozen ...>`` marker or a plaintext file path."""
    p = str(pathname)
    if p.startswith(_FROZEN_PREFIX):
        return p[len(_FROZEN_PREFIX):-1]     # '<frozen pkg.sub.mod>' -> 'pkg.sub.mod'
    return _path_to_dotted(p)


def _apply(record: logging.LogRecord, only_packages) -> None:
    dotted = defrost_module(record.pathname)
    if only_packages and dotted.split(".", 1)[0] not in only_packages:
        return                               # leave third-party/stdlib default alone
    record.module = dotted
    # keep filename/pathname internally consistent with the recovered name
    record.filename = dotted.rsplit(".", 1)[-1] + ".py"
    if str(record.pathname).startswith(_FROZEN_PREFIX):
        record.pathname = dotted.replace(".", "/") + ".py"


def install(only_packages=None) -> None:
    """Install the record-factory fix (idempotent).

    only_packages: optional iterable of top-level package names; when given, only
    records whose recovered dotted name starts with one of them are rewritten, so
    third-party/stdlib log lines keep logging's default (basename) module field.
    """
    global _ORIGINAL_FACTORY, _INSTALLED
    only = frozenset(only_packages) if only_packages else None
    if _ORIGINAL_FACTORY is None:
        _ORIGINAL_FACTORY = logging.getLogRecordFactory()
    base = _ORIGINAL_FACTORY

    def factory(*args, **kwargs):
        record = base(*args, **kwargs)
        try:
            _apply(record, only)
        except Exception:
            pass                             # never let logging repair break logging
        return record

    logging.setLogRecordFactory(factory)
    _INSTALLED = True


class DefrostFilter(logging.Filter):
    """dictConfig-friendly equivalent of :func:`install`, for the case where a
    custom Logger subclass bypasses the record factory.  Attach to handlers."""

    def __init__(self, name: str = "", only_packages=None):
        super().__init__(name)
        self.only_packages = frozenset(only_packages) if only_packages else None

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            _apply(record, self.only_packages)
        except Exception:
            pass
        return True


# Auto-install on import so `import antirev_log_fix` is enough.
install()
