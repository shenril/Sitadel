import logging


def setup_logging(verbosity=0, logfile="sitadel.log"):
    """Configure and return the ``sitadelLog`` logger.

    The file handler always records at INFO level so ``sitadel.log`` captures
    the scan details (including the ERROR records emitted by the modules)
    regardless of ``--verbosity``. ``--verbosity`` only controls how much is
    echoed to the console. Previously the whole logger inherited the root
    level set to ``CRITICAL`` by default, so nothing was ever written to the
    file unless ``-v`` was passed (see issue #45).
    """
    logger = logging.getLogger("sitadelLog")
    logger.setLevel(logging.DEBUG)
    # Do not let records bubble up to the root logger (avoids duplicate output)
    logger.propagate = False
    # Reset handlers so repeated calls don't stack duplicates
    logger.handlers.clear()

    # File handler: always capture the run details.
    file_handler = logging.FileHandler(logfile, mode="w", encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_handler.setFormatter(
        logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            datefmt="%d-%b-%y %H:%M:%S",
        )
    )

    # Console handler: driven by --verbosity, but errors stay visible by default.
    console_handler = logging.StreamHandler()
    console_handler.setLevel(min(logging.WARNING, logging.CRITICAL - (verbosity * 10)))
    console_handler.setFormatter(
        logging.Formatter("%(name)s - %(levelname)s - %(message)s")
    )

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger
