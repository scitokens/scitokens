"""
Module for configuration management

"""


# Config parser is renamed in python 3
import configparser
import logging
import logging.handlers

# Set the default cache lifetime fo 4 days
CONFIG_DEFAULTS = {
    'log_file': "",
    'log_level': "INFO",
    'cache_lifetime': "345600",
    'cache_location': "",
    'default_alg': "RS256"
}

configuration = configparser.ConfigParser(CONFIG_DEFAULTS) # pylint: disable=C0103

def set_config(config = None):
    """
    Set the configuration of SciTokens library

    :param config: config may be: A full path to a ini configuration file,
        a ConfigParser instance, or None, which will use all defaults.
    """
    global configuration # pylint: disable=C0103

    if isinstance(config, str):
        configuration = configparser.ConfigParser(CONFIG_DEFAULTS)
        configuration.read([config])
    elif isinstance(config, configparser.RawConfigParser):
        configuration = config
    elif config is None:
        print("Using built-in defaults")
        configuration = configparser.ConfigParser(CONFIG_DEFAULTS)
        configuration.add_section("scitokens")
    else:
        pass

    logger = logging.getLogger("scitokens")

    if configuration.has_option("scitokens", "log_file"):
        log_file = configuration.get("scitokens", "log_file")
        if log_file != "":
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

def configure(**params):
    """
    Alternative way to configuration the SciTokens library without using a configuration file.

    :param params: keyword arguments:

        * log_file: str, log file location, default: ""
        * log_level: str, default: "INFO",
        * cache_lifetime: int, default: 345600 = 96 hours,
        * cache_location: str, cache, ``"__memory__"`` is a special value, whicn means use non-persistent, thread-safe in-memory cache. default: "".
        * default_alg: str, default: "RS256",
    """
    global configuration # pylint: disable=C0103

    cfg = CONFIG_DEFAULTS.copy()
    cfg.update({k:v for k, v in params.items() if k in cfg})
    configuration = configparser.ConfigParser(cfg)
    configuration.add_section("scitokens")


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

