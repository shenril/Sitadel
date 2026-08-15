import logging
import os

from lib.utils.logs import setup_logging


def _read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def test_file_captures_errors_by_default(tmp_path):
    logfile = os.path.join(str(tmp_path), "sitadel.log")

    # Default verbosity (0): the file must still capture ERROR records.
    logger = setup_logging(verbosity=0, logfile=logfile)
    logger.error("boom-error")
    logger.info("some-info")
    for handler in logger.handlers:
        handler.flush()

    content = _read(logfile)
    if "boom-error" not in content:
        raise AssertionError("ERROR records should be written to the log file")
    if "some-info" not in content:
        raise AssertionError("INFO records should be written to the log file")


def test_logger_is_configured(tmp_path):
    logfile = os.path.join(str(tmp_path), "sitadel.log")
    logger = setup_logging(verbosity=0, logfile=logfile)

    if logger.name != "sitadelLog":
        raise AssertionError
    # DEBUG at the logger level so handlers decide what to emit.
    if logger.level != logging.DEBUG:
        raise AssertionError
    # One file + one console handler, no duplicates on repeated setup.
    setup_logging(verbosity=0, logfile=logfile)
    if len(logger.handlers) != 2:
        raise AssertionError
    if not any(isinstance(h, logging.FileHandler) for h in logger.handlers):
        raise AssertionError
