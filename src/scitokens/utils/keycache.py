import os
import sqlite3
import time

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

CACHE_FILENAME = "scitokens_keycache.sqllite"

class UnableToWriteKeyCache(Exception):
    """
    For whatever reason, unable to write to the Key Cache
    """
    pass

class KeyCache(object):
    def __init__(self):
        
        # Check for the cache
        self.cache_location = self._get_cache_file()
        
    def getKeyInfo(issuer, key_id=None, insecure=False):
        """
        Get the key information
        
        :param str issuer: The issuer URI
        :param str key_id: Text key id to identify the key
        :returns: None if no key is found.  Else, returns the public key
        """
        # Check the sql database 
        key_query = ("SELECT * FROM keycache WHERE "
                     "issuer = {issuer}")
        if key_id != None:
            key_query += "AND key_id = {key_id}"
        conn = sqlite3.connect(self.cache_location)
        curs = conn.cursor()
        curs.execute(key_query.format(issuer=issuer, key_id=key_id)):
        
        row = curs.fetchone()
        if row != None:
            return self.checkValidity(row)
        
        # If it reaches here, then no key was found in the SQL
        # Try checking the issuer (negative cache?)
        public_key = self._get_issuer_publickey(issuer, key_id, insecure)
        
        # Add the key to the cache
        insert_key_statement = "INSERT INTO keycache VALUES({issuer}, {expiration}, {key_id}, {keydata})"
        keydata = public_key.public_bytes(Encoding.PEM, PublicFormat.PKCS1).decode('ascii')
        curs.execute(insert_key_statement.format(issuer=issuer, expiration=time.time()+60, key_id=key_id, keydata=keydata))
        if curs.rowcount != 1:
            throw UnableToWriteKeyCache("Unable to insert into key cache")
        
        return public_key
        
    
    def _get_issuer_publickey(issuer, key_id=None, insecure=False):
        
        # Set the user agent so Cloudflare isn't mad at us
        headers={'User-Agent': 'SciTokens/{}'.format(PKG_VERSION)}
        
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
        if not insecure:
            parsed_url = urlparse.urlparse(meta_uri)
            if parsed_url.scheme != "https":
                raise NonHTTPSIssuer("Issuer is not over HTTPS.  RFC requires it to be over HTTPS")
        response = request.urlopen(request.Request(meta_uri, headers=headers))
        data = json.loads(response.read().decode('utf-8'))
        
        # Get the keys URL from the openid-configuration
        jwks_uri = data['jwks_uri']
        
        # Now, get the keys
        if not insecure:
            parsed_url = urlparse.urlparse(jwks_uri)
            if parsed_url.scheme != "https":
                raise NonHTTPSIssuer("jwks_uri is not over HTTPS, insecure!")
        response = request.urlopen(request.Request(jwks_uri, headers=headers))
        keys_data = json.loads(response.read().decode('utf-8'))
        # Loop through each key, looking for the right key id
        public_key = ""
        raw_key = None
        
        # If there is no kid in the header, then just take the first key?
        if key_id == None:
            if len(keys_data['keys']) != 1:
                raise NotImplementedError("No kid in header, but multiple keys in "
                                          "response from certs server.  Don't know which key to use!")
            else:
                raw_key = keys_data['keys'][0]
        else:
            # Find the right key
            for key in keys_data['keys']:
                if key['kid'] == key_id:
                    raw_key = key
                    break

        if raw_key == None:
            raise MissingKeyException("Unable to find key at issuer {}".format(jwks_uri))

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
                   ec.SECP256R1
               )
            public_key = public_key_numbers.public_key(backends.default_backend())
        else:
            raise UnsupportedKeyException("SciToken signed with an unsupported key type")
        
        return public_key
    
    
    def _get_cache_file(self):
        """
        Get the Cache file location
        
        1. $XDG_CACHE_HOME
        2. $HOME/.cache
        """
        
        xdg_cache_home = os.environ.get("XDG_CACHE_HOME", None)
        home_dir = os.environ.get("HOME", None)
        
        if xdg_cache_home != None:
            cache_dir = xdg_cache_dir
        elif home_dir != None:
            cache_dir = os.path.join(home_dir, ".cache")
        
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)
            
        keycache_dir = os.path.join(cache_dir, "scitokens")
        if not os.path.exists(keycache_dir):
            os.makedirs(keycache_dir)
            
        keycache_file = os.path.join(keycache_dir, CACHE_FILENAME)
        if not os.path.exists(keycache_file):
            self._initialize_cachedb(keycache_file)
            
        return keycache_file
    
    def _initialize_cachedb(self, sql_file):
        """
        Create a simple flat sqllite cache
        """
        conn = sqlite3.connect(self.cache_location)
        curs = conn.cursor()
        
        # Create cache table
        curs.execute ("CREATE TABLE keycache ("
                      "issuer text NOT NULL,"
                      "expiration integer NOT NULL,"
                      "key_id text,"
                      "keydata text NOT NULL,"
                      "PRIMARY KEY (issuer, key_id))")
        # Save (commit) the changes
        conn.commit()
        
        # We can also close the connection if we are done with it.
        # Just be sure any changes have been committed or they will be lost.
        conn.close()
        