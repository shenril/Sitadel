import logging

# Progressive ``-v`` scale applied to the log file. Each extra ``-v`` lowers
# the threshold one step, so more is written to ``sitadel.log``:
#
#   (no flag) -> ERROR    only errors
#   -v        -> WARNING  warnings + errors
#   -vv       -> INFO     progress + findings (+ above)
#   -vvv      -> DEBUG    crawler paths + every tested pattern (+ above)
#
# ``-vvv`` and beyond all map to DEBUG (the most detailed level).
_FILE_LEVELS = {
    0: logging.ERROR,
    1: logging.WARNING,
    2: logging.INFO,
}


def verbosity_to_level(verbosity: int) -> int:
    """Map a ``-v`` count to a :mod:`logging` level using the progressive scale."""
    return _FILE_LEVELS.get(verbosity, logging.DEBUG)


def setup_logging(verbosity=0, logfile="sitadel.log"):
    """Configure and return the ``sitadelLog`` logger (the file sink).

    The console is owned by :class:`lib.utils.output.Output`; this logger owns
    the *file* only, so ``sitadel.log`` can hold strictly more detail than what
    is echoed to stdout.

    ``verbosity`` (the ``-v`` count) drives how much is written to the file via
    the progressive scale in :data:`_FILE_LEVELS`: ``-v`` warnings, ``-vv``
    info/findings, ``-vvv`` full debug (crawler paths and every payload/pattern
    the attack modules test).

    Previously the file handler was pinned to ``INFO`` and nothing in the
    success path ever logged to it, so a clean run left ``sitadel.log`` empty
    regardless of ``-v`` (see issue #45 and the follow-up on empty logs).
    """
    logger = logging.getLogger("sitadelLog")
    logger.setLevel(logging.DEBUG)
    # Do not let records bubble up to the root logger (avoids duplicate output).
    logger.propagate = False
    # Reset handlers so repeated calls don't stack duplicates.
    logger.handlers.clear()

    file_level = verbosity_to_level(verbosity)
    file_handler = logging.FileHandler(logfile, mode="w", encoding="utf-8")
    file_handler.setLevel(file_level)
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s - %(levelname)s - %(message)s",
            datefmt="%d-%b-%y %H:%M:%S",
        )
    )
    logger.addHandler(file_handler)
    return logger
