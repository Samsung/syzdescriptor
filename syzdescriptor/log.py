import logging, sys

class SyzdescriptorFormatter(logging.Formatter):
    BASE_FORMAT = '[syzdescriptor][%(asctime)s][%(levelname)s] %(message)s'
    ESCAPE_CODES = {
        'reset': '\x1B[0m',
        'red': '\x1B[31m',
        'yellow': '\x1B[33m',
        'bold_red': '\x1B[31;1m',
    }

    FORMATS = {
        logging.DEBUG: BASE_FORMAT,
        logging.INFO: BASE_FORMAT,
        logging.WARNING: ESCAPE_CODES['yellow']
                       + BASE_FORMAT
                       + ESCAPE_CODES['reset'],
        logging.ERROR: ESCAPE_CODES['red']
                     + BASE_FORMAT
                     + ESCAPE_CODES['reset'],
        logging.CRITICAL: ESCAPE_CODES['bold_red']
                        + BASE_FORMAT
                        + ESCAPE_CODES['reset'],
    }

    def __init__(self, colored = False):
        self.colored = colored

    def format(self, record):
        fmt = self.BASE_FORMAT
        if self.colored:
            fmt = self.FORMATS[record.levelno]

        return logging.Formatter(fmt).format(record)

def setup_logging(verbose):
    sh = logging.StreamHandler()
    sh.setFormatter(SyzdescriptorFormatter(sys.stdout.isatty()))
    logging.getLogger().addHandler(sh)
    if verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)
