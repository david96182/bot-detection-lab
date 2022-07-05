import sys
import traceback
import logging.handlers
from configparser import ConfigParser

CONFIG_PATH = './config.ini'


def get_config():
    config = ConfigParser()
    config.read(CONFIG_PATH)
    logging.info(f'Reading config file {CONFIG_PATH}')
    return config


log_name = get_config()['log']['log_file']
log_path = get_config()['log']['log_path']
full_log_path = str(log_path + '/' + log_name)

# log_handler = logging.StreamHandler(sys.stdout)
log_handler = logging.handlers.WatchedFileHandler(full_log_path)
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
