import logging
import os.path
import sys
import traceback
import logging.handlers
from configparser import ConfigParser

import pyshark.tshark.tshark

CONFIG_PATH = '../config.ini'


def get_config():
    config = ConfigParser()
    print(os.path.join(os.path.dirname(__file__)))
    config.read(os.path.join(os.path.dirname(__file__)), 'config.ini')
    return config


def verify_interface(interface):
    interfaces = pyshark.tshark.tshark.get_tshark_interfaces()
    if interface in interfaces:
        return True
    return False


# log_handler = logging.StreamHandler(sys.stdout)
log_handler = logging.handlers.WatchedFileHandler('/home/david/logs/bto_logs.log')
log_format = logging.Formatter(r'%(asctime)s %(levelname)s [%(pathname)s:%(lineno)s] %(message)s')
log_handler.setFormatter(log_format)
logger = logging.getLogger()
logger.addHandler(log_handler)
logger.setLevel(logging.INFO)


def hook(exctype, value, tb):
    traceback.print_exception(exctype, value, tb)
    sys.__excepthook__(exctype, value, tb)


sys.excepthook = hook


class LoggerRedirect(object):
    def __init__(self, logger, level=logging.INFO):
        self.logger = logger
        self.level = level

    def write(self, message):
        if message and message != '\n':
            try:
                self.logger.log(self.level, message)
            except Exception as e:
                sys.stderr.write("unhandled exception %s trying to log %s" %
                                 (e, message))

    def flush(self):
        pass

    def patch_sys(self):
        self.old_stdout = sys.stdout
        sys.stdout = self


redirect = LoggerRedirect(logger)
