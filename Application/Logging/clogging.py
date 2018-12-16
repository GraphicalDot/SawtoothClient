import logging
from logging.config import fileConfig
import os
from os.path import dirname, abspath
LOG_PATH = dirname(dirname(abspath(__file__)))

import logging.config
# load config from file
# logging.config.fileConfig('logging.ini', disable_existing_loggers=False)
# or, for dictConfig
#logger = logging.getLogger(__name__)
from colorlog import ColoredFormatter

dictConfig = {
    "version": 1,
    "disable_existing_loggers": True,
    "formatters": {
                'simple': {'()': 'coloredlogs.ColoredFormatter', 'format': "%(asctime)s - %(name)s - %(levelname)s - %(message)s", 'datefmt': '%H:%M:%S'},
    },

    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "level": "CRITICAL",
            "formatter": "simple",
            "stream": "ext://sys.stdout"
        },

        "info_file_handler": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "DEBUG",
            "formatter": "simple",
            "filename": "info.log",
            "maxBytes": 10485760,
            "backupCount": 20,
            "encoding": "utf8"
        },

        "error_file_handler": {
            "class": "logging.handlers.RotatingFileHandler",
            "level": "ERROR",
            "formatter": "simple",
            "filename": "errors.log",
            "maxBytes": 10485760,
            "backupCount": 20,
            "encoding": "utf8"
        }
    },

    "loggers": {
        "my_module": {
            "level": "ERROR",
            "handlers": ["console"],
            "propagate": "no"
        }
    },

    "root": {
        "level": "INFO",
        "handlers": ["console", "info_file_handler", "error_file_handler"]
    }
}

logging.config.dictConfig(dictConfig)
logger = logging.getLogger("root")
#logging.basicConfig(level=logging.DEBUG,  format="%(asctime)s:%(levelname)s:%(message)s")
