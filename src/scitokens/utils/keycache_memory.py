
"""
A module for thread-safely caching the public keys of various token issuer endpoints in memory.
"""

import time
import re
import logging
import json
from threading import RLock
from cryptography.hazmat import backends
from cryptography.hazmat.primitives.asymmetric import ec, rsa
import pkg_resources  # part of setuptools
from scitokens.utils.errors import MissingKeyException, NonHTTPSIssuer, UnsupportedKeyException
from scitokens.utils import long_from_bytes
from scitokens.utils import config

try:
    PKG_VERSION = pkg_resources.require("scitokens")[0].version
except pkg_resources.DistributionNotFound:
    # During testing, scitokens won't be installed, so requiring it will fail
    # Instead, fake it
    PKG_VERSION = '1.0.0'

try:
    from urllib import request
except ImportError:
    import urllib2 as request

try:
    import urlparse
except ImportError:
    import urllib.parse as urlparse


def _get_issuer_publickey(issuer, key_id=None, insecure=False): # pylint: disable=R0914 disable=R0912 disable=R0915
    """
    :return: tuple: (public_key, key_id, cache_timer)
    """

    # Set the user agent so Cloudflare isn't mad at us
    headers={'User-Agent' : f'SciTokens/{PKG_VERSION}'}

    # Go to the issuer's website, and download the OAuth well known bits
    # https://tools.ietf.org/html/draft-ietf-oauth-discovery-07
    well_known_uri = ".well-known/openid-configuration"
    if not issuer.endswith("/"):
        issuer = issuer + "/"
    parsed_url = urlparse.urlparse(issuer)
    updated_url = urlparse.urljoin(parsed_url.path, well_known_uri)
    parsed_url_list = list(parsed_url)
    parsed_url_list[2] = updated_url
    meta_uri = urlparse.urlunparse(parsed_url_list)

    # Make sure the protocol is https
    if not insecure and parsed_url.scheme != "https":
        raise NonHTTPSIssuer("Issuer is not over HTTPS.  RFC requires it to be over HTTPS")
    response = request.urlopen(request.Request(meta_uri, headers=headers))  #nosec
    data = json.loads(response.read().decode('utf-8'))

    # Get the keys URL from the openid-configuration
    jwks_uri = data['jwks_uri']

    # Now, get the keys
    if not insecure:
        parsed_url = urlparse.urlparse(jwks_uri)
        if parsed_url.scheme != "https":
            raise NonHTTPSIssuer("jwks_uri is not over HTTPS, insecure!")
    response = request.urlopen(request.Request(jwks_uri, headers=headers))  #nosec

    # Get the cache data from the headers
    cache_timer = 0
    headers = response.info()
    cache_control = headers.get('Cache-Control')
    if cache_control and "max-age" in cache_control:
        match = re.search(r".*max-age=(\d+)", cache_control)
        if match:
            cache_timer = int(match.group(1))
    # Minimum cache time of 10 minutes, no matter what the remote says
    cache_timer = max(cache_timer, config.get_int("cache_lifetime"))

    keys_data = json.loads(response.read().decode('utf-8'))
    # Loop through each key, looking for the right key id
    public_key = ""
    raw_key = None

    # If there is no kid in the header, then just take the first key?
    if key_id is None:
        if len(keys_data['keys']) != 1:
            raise NotImplementedError("No kid in header, but multiple keys in "
                                      "response from certs server.  Don't know which key to use!")
        raw_key = keys_data['keys'][0]
    else:
        # Find the right key
        for key in keys_data['keys']:
            if key['kid'] == key_id:
                raw_key = key
                break

    if raw_key is None:
        raise MissingKeyException(f"Unable to find key at issuer {jwks_uri}")

    if raw_key['kty'] == "RSA":
        public_key_numbers = rsa.RSAPublicNumbers(
            long_from_bytes(raw_key['e']),
            long_from_bytes(raw_key['n'])
        )
        public_key = public_key_numbers.public_key(backends.default_backend())
    elif raw_key['kty'] == 'EC':
        public_key_numbers = ec.EllipticCurvePublicNumbers(
               long_from_bytes(raw_key['x']),
               long_from_bytes(raw_key['y']),
               ec.SECP256R1()
           )
        public_key = public_key_numbers.public_key(backends.default_backend())
    else:
        raise UnsupportedKeyException("SciToken signed with an unsupported key type")

    return public_key, raw_key.get("key_id"), cache_timer

class KeyInfo:
    """
    Issuers public key and attributes necessary to keep it in the cache
    """

    DefaultUpdateInterval = 3600

    def __init__(self, issuer, key_id, key, expiration, allow_insecure, next_update=None):  # pylint: disable=R0913
        self.Lock = RLock()         # pylint: disable=C0103
        self.Issuer = issuer        # pylint: disable=C0103
        self.KeyID = key_id         # pylint: disable=C0103
        self.Key = key              # pylint: disable=C0103
        self.NextUpdate = next_update or time.time() + self.DefaultUpdateInterval           # pylint: disable=C0103
        self.AllowInsecure = allow_insecure                                                 # pylint: disable=C0103
        # check if expiration the is actually an interval (<10 years) or absolute (>1/1/1980)
        self.Expiration = expiration if expiration > 3e8 else time.time() + expiration      # pylint: disable=C0103

    # consider the key expired if its expiration is less than 10 seconds away
    ExpirationMargin = 10

    @property
    def is_valid(self):
        """is it valid ?
        """
        return self.Expiration - self.ExpirationMargin > time.time()

    @property
    def key(self):
        """refresh the key if needed and return the key object (not KeyInfo)
        """
        with self.Lock:
            if time.time() > self.NextUpdate:
                try:
                    # Get the public key, probably from a webserver
                    public_key, key_id, expiration = _get_issuer_publickey(
                            self.Issuer, self.KeyID, self.AllowInsecure)
                    self.Expiration = expiration
                    self.Key = public_key
                    self.KeyID = key_id
                except Exception as ex:         # pylint: disable=W0703
                    logger = logging.getLogger("scitokens")
                    logger.warning(f"Unable to get key triggered by next update: {ex}") # pylint: disable=W1203
        return self.Key



class KeyCacheMemory:
    """
    Thread-safe in-memory cache for keys associated with a token issuer endpoint.
    """

    InstanceLock = RLock()
    Instance = None

    def __init__(self):
        # Check for the cache
        self.Cache = {}                 # { (issuer, key_id) -> KeyInfo() }         # pylint: disable=C0103
        self.Lock = RLock()                                                         # pylint: disable=C0103

    @classmethod
    def getinstance(cls):
        """
        Return the singleton instance of the KeyCache.
        """

        with cls.InstanceLock:
            if cls.Instance is None:
                cls.Instance = KeyCacheMemory()
        return cls.Instance

    def addkeyinfo(self, issuer, key_id, public_key, cache_timer=0, next_update=0): # pylint: disable=R0913
        # used internally only
        """
        Add a single, known public key to the cache.

        :param str issuer: URI of the issuer
        :param str key_id: Key Identifier
        :param public_key: Cryptography public_key object
        :param int cache_timer: Cache lifetime of the public_key
        :param int next_update: Seconds until next update time
        """

        with self.Lock:
            self.Cache[(issuer, key_id or "")] = key_info = KeyInfo(
                    issuer, key_id, public_key, cache_timer, False, next_update=next_update
            )
        return key_info

    def _parse_key_data(self, issuer, kid, keydata):
        """
        Keydata is stored as a JSON object inside the DB.  Therefore, we must extract it.

        :param str issuer: Token Issuer in keydata
        :param str kid: Key ID
        :param str keydata: Raw JSON key data (at least, it should be)
        :param curs: SQLite cursor, in case it has to delete the row

        :returns str: encoded public key, otherwise None
        """

        # First, get the key data
        try:
            return json.loads(keydata)['pub_key']
        except ValueError:
            logging.exception("Unable to parse JSON stored in keycache.  "
                              "This likely means the database format needs"
                              "to be updated, which we will now do automatically")

            self._delete_cache_entry(issuer, kid)
            return None

    def _delete_cache_entry(self, issuer, key_id):
        """
        Delete a cache entry
        """
        with self.Lock:
            self.Cache.pop((issuer, key_id or ""), None)

    def getkeyinfo(self, issuer, key_id=None, insecure=False):
        """
        Get the key information

        :param str issuer: The issuer URI
        :param str key_id: Text key id to identify the key
        :param bool insecure: Whether insecure methods are acceptable (defaults to False).
        :returns: None if no key is found.  Else, returns the public key
        """


        key_info = None
        with self.Lock:
            if not key_id:
                key_info = self.Cache.get((issuer, key_id or ""))
            else:
                #
                # If key_id is None (?) and there are multiple keys to choose from,
                # find the one with the longest lifetime
                #
                for (iss, _), k in self.Cache.items():
                    if iss == issuer:
                        if key_info is None or k.Expiration > key_info.Expiration:
                            key_info = k

        if key_info is not None and not key_info.is_valid:
            self._delete_cache_entry(issuer, key_info.KeyID)
            key_info = None

        if key_info is None:
            key, key_id, expiration = _get_issuer_publickey(issuer, key_id, insecure)
            self.Cache[(issuer, key_id or "")] = key_info = KeyInfo(
                    issuer, key_id, key, expiration, insecure
            )

        return key_info and key_info.key

def getinstance():
    """
    Returns KeyCacheMemory instance
    """
    return KeyCacheMemory.getinstance()
