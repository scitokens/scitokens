
# Config parser is renamed in python 3
from six.moves import configparser
import logging
import logging.handlers

config_defaults = {
    'log_file': None,
    'log_level': "INFO",
    'cache_lifetime': 60
}


def set_config(config = None):
    global configuration
    
    if isinstance(config, basestring):
        configuration = configparser.SafeConfigParser(config_defaults)
        configuration.read([config])
    elif isinstance(config, configparser.RawConfigParser):
        configuration = config
    elif config is None:
        print("Using built-in defaults")
        configuration = configparser.SafeConfigParser(config_defaults)
    else:
        pass
    
    logger = logging.getLogger("scitokens")

    if configuration.has_option("scitokens", "log_file"):
        log_file = configuration.get("scitokens", "log_file")
        if log_file is not None:
            # Create loggers with 100MB files, rotated 5 times
            logger.addHandler(logging.handlers.RotatingFileHandler(log_file, maxBytes=100 * (1024*1000), backupCount=5))
        
    else:
        logger.addHandler(logging.StreamHandler())
    
    # Set the logging
    log_level = configuration.get("scitokens", "log_level")
    if log_level == "DEBUG":
        logger.setLevel(logging.DEBUG)
    elif log_level == "INFO":
        logger.setLevel(logging.INFO)
    elif log_level == "WARNING":
        logger.setLevel(logging.WARNING)
    elif log_level == "ERROR":
        logger.setLevel(logging.ERROR)
    elif log_level == "CRITICAL":
        logger.setLevel(logging.CRITICAL)
    else:
        logger.setLevel(logging.WARNING)
    

        


def get(key, default=None):
    """
    Get the configuration value for key
    """
    global configuration

    try:
        return configuration.get("scitokens", key)
    except configparser.NoOptionError as noe:
        # Check the defaults
        if key in config_defaults:
            return config_defaults[key]
        else:
            raise noe
        







