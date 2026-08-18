import logging
import os

from lib.utils.logs import setup_logging


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def test_file_captures_errors_by_default(tmp_path):
    logfile = os.path.join(str(tmp_path), "sitadel.log")

    # Default verbosity (0): the file is ERROR-only. Errors are captured;
    # lower-severity records are dropped until -v raises the level.
    logger = setup_logging(verbosity=0, logfile=logfile)
    logger.error("boom-error")
    logger.info("some-info")
    for handler in logger.handlers:
        handler.flush()

    content = _read(logfile)
    if "boom-error" not in content:
        raise AssertionError("ERROR records should be written to the log file")
    if "some-info" in content:
        raise AssertionError("INFO must be dropped from the file at -v0 (ERROR-only)")


def test_logger_is_configured(tmp_path):
    logfile = os.path.join(str(tmp_path), "sitadel.log")
    logger = setup_logging(verbosity=0, logfile=logfile)

    if logger.name != "sitadelLog":
        raise AssertionError
    # DEBUG at the logger level so the handler decides what to emit.
    if logger.level != logging.DEBUG:
        raise AssertionError
    # The logger owns the file only (the console is owned by Output); a single
    # file handler, with no duplicates on repeated setup.
    setup_logging(verbosity=0, logfile=logfile)
    if len(logger.handlers) != 1:
        raise AssertionError
    if not isinstance(logger.handlers[0], logging.FileHandler):
        raise AssertionError


def test_verbosity_maps_to_progressive_file_level(tmp_path):
    logfile = os.path.join(str(tmp_path), "sitadel.log")

    # The progressive -v scale: each extra -v lowers the file handler one step.
    expected = {
        0: logging.ERROR,
        1: logging.WARNING,
        2: logging.INFO,
        3: logging.DEBUG,
        4: logging.DEBUG,  # -vvvv and beyond stay at DEBUG
    }
    for verbosity, level in expected.items():
        logger = setup_logging(verbosity=verbosity, logfile=logfile)
        if logger.handlers[0].level != level:
            raise AssertionError(
                f"-v{verbosity} should map the file handler to {level}, "
                f"got {logger.handlers[0].level}"
            )


def test_debug_detail_only_appears_at_vvv(tmp_path):
    logfile = os.path.join(str(tmp_path), "sitadel.log")

    # -vv (INFO): info kept, DEBUG detail dropped.
    logger = setup_logging(verbosity=2, logfile=logfile)
    logger.info("kept-info")
    logger.debug("quiet-debug")
    for handler in logger.handlers:
        handler.flush()
    content = _read(logfile)
    if "kept-info" not in content:
        raise AssertionError("INFO must be kept in the file at -vv")
    if "quiet-debug" in content:
        raise AssertionError("DEBUG must be dropped from the file at -vv")

    # -vvv (DEBUG): the detail is captured.
    logger = setup_logging(verbosity=3, logfile=logfile)
    logger.debug("loud-debug")
    for handler in logger.handlers:
        handler.flush()
    if "loud-debug" not in _read(logfile):
        raise AssertionError("DEBUG must be written to the file at -vvv")
