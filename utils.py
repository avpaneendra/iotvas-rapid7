import sys
import os
import logging
import logging.handlers
from logging.handlers import TimedRotatingFileHandler
import base64

import iotvas
import rapid7vmconsole
from config import app_config


def get_logger(name, level, folder):
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(name)
    logger.setLevel(level)
    file_handler = TimedRotatingFileHandler(os.path.join(folder, "iotvas-rapid7"),
                                           when = 'd',
                                           interval = 1,
                                           backupCount = 0)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    return logger

def get_iotvas_client():
    config = iotvas.Configuration("iotvas")
    config.host = app_config['iotvas_url']
    config.api_key = app_config['iotvas_apikey']
    client = iotvas.ApiClient(configuration=config)
    client.default_headers['x-api-key'] = config.api_key
    return client

def get_vmconsole_client():
    config = rapid7vmconsole.Configuration(name='rapid7')
    config.username = app_config['vmconsole_user']
    config.password = app_config['vmconsole_password']
    config.host = app_config['vmconsole_url']
    config.verify_ssl = app_config['vmconsole_verifyssl']
    config.assert_hostname = app_config['vmconsole_assert_hostname']
    config.proxy = app_config['vmconsole_proxy']
    config.ssl_ca_cert = app_config['vmconsole_ssl_ca_cert']
    config.connection_pool_maxsize = None
    config.cert_file = app_config['vmconsole_certfile']
    config.key_file = app_config['vmconsole_keyfile']


    config.safe_chars_for_path_param = ''
    auth = "%s:%s" % (config.username, config.password)
    auth = base64.b64encode(auth.encode('ascii')).decode()
    client = rapid7vmconsole.ApiClient(configuration=config)
    client.default_headers['Authorization'] = "Basic %s" % auth
    return client
