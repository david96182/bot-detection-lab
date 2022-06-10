from configparser import ConfigParser
import pyshark.tshark.tshark
import logging

CONFIG_PATH = './config.ini'


def get_config():
    config = ConfigParser()
    config.read(CONFIG_PATH)
    logging.info(f'Reading config file {CONFIG_PATH}')
    return config


def verify_interface(interface):
    interfaces = pyshark.tshark.tshark.get_tshark_interfaces()
    if interface in interfaces:
        return True
    return False