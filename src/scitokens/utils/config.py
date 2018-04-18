"""
Module for configuration management

"""


# Config parser is renamed in python 3
from six.moves import configparser
import six
import logging
import logging.handlers

CONFIG_DEFAULTS = {
    'log_file': None,
    'log_level': "INFO",
    'cache_lifetime': "3600",
    'cache_location': None,
    'default_alg': "RS256"
}

configuration = configparser.SafeConfigParser(CONFIG_DEFAULTS) # pylint: disable=C0103

def set_config(config = None):
    """
    Set the configuration of SciTokens library
    :param config: config may be: A full path to a ini configuration file,
        A ConfigParser instance, or None, which will use all defaults.
    """
    global configuration # pylint: disable=C0103

    if isinstance(config, six.string_types):
        configuration = configparser.SafeConfigParser(CONFIG_DEFAULTS)
        configuration.read([config])
    elif isinstance(config, configparser.RawConfigParser):
        configuration = config
    elif config is None:
        print("Using built-in defaults")
        configuration = configparser.SafeConfigParser(CONFIG_DEFAULTS)
        configuration.add_section("scitokens")
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

    :param str key: The key in the configuration to retreive
    :returns: The value in the configuration, or the default
    """
    del default
    global configuration # pylint: disable=C0103

    try:
        return configuration.get("scitokens", key)
    except (configparser.NoOptionError, configparser.NoSectionError) as noe:
        # Check the defaults
        if key in CONFIG_DEFAULTS:
            return CONFIG_DEFAULTS[key]
        else:
            raise noe


def get_int(key, default=None):
    """
    Get an integer from the configuration.

    :param str key: The key in the configuration to retreive
    :returns: The value in the configuration, or the default
    """
    return int(get(key, default))

