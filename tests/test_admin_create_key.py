"""
Test the admin-create-key tool
"""

import os
import sys
import unittest
import subprocess
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import json
import tempfile

# Allow unittests to be run from within the project base.
if os.path.exists("src"):
    sys.path.append("src")
if os.path.exists("../src"):
    sys.path.append("../src")

from scitokens.utils import long_from_bytes

class TestKeyCreate(unittest.TestCase):
    """
    Test the admin-create-key tool
    """

    to_delete = []

    def setUp(self):
        os.environ['PYTHONPATH'] = ":".join(sys.path)

    @staticmethod
    def _test_private(key):
        return serialization.load_pem_private_key(
            key,
            password=None,
            backend=default_backend()
        )

    @staticmethod
    def _test_public(key):
        return serialization.load_pem_public_key(
            key,
            backend=default_backend()
        )

    @staticmethod
    def _test_public_jwk(key):
        """
        Attempt to read in the key into a key object
        """
        keys = json.loads(key)
        public_key_numbers = rsa.RSAPublicNumbers(
            long_from_bytes(keys['keys'][0]['e']),
            long_from_bytes(keys['keys'][0]['n'])
        )
        return public_key_numbers.public_key(default_backend())

    @staticmethod
    def _test_private_jwk(key):
        """
        Attempt to read in the key into a private key object
        """
        keys = json.loads(key)
        public_key_numbers = rsa.RSAPublicNumbers(
            long_from_bytes(keys['keys'][0]['e']),
            long_from_bytes(keys['keys'][0]['n'])
        )
        private_key_numbers = rsa.RSAPrivateNumbers(
            long_from_bytes(keys['keys'][0]['p']),
            long_from_bytes(keys['keys'][0]['q']),
            long_from_bytes(keys['keys'][0]['d']),
            long_from_bytes(keys['keys'][0]['dp']),
            long_from_bytes(keys['keys'][0]['dq']),
            long_from_bytes(keys['keys'][0]['qi']),
            public_key_numbers
        )
        return private_key_numbers.private_key(default_backend())
        
        
    def _run_command(self, command):
        command_run = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdout, stderr) = command_run.communicate()
        if command_run.returncode != 0:
            print(stdout)
            print(stderr)
            self.assertEqual(command_run.returncode, 0)
        return stdout


    def test_create(self):
        """
        Test the key creation
        """
        command = "python tools/scitokens-admin-create-key --create-keys --pem-private"
        output = self._run_command(command)
        private_key = self._test_private(output)
        self.assertIsNotNone(private_key)

        # Test public key
        command = "python tools/scitokens-admin-create-key --create-keys --pem-public"
        output = self._run_command(command)
        public_key = self._test_public(output)
        self.assertIsNotNone(public_key)

        # Test public key
        command = "python tools/scitokens-admin-create-key --create-keys --jwks-private"
        output = self._run_command(command)
        private_key = self._test_private_jwk(output)
        self.assertIsNotNone(public_key)

        # Test public key
        command = "python tools/scitokens-admin-create-key --create-keys --jwks-public"
        output = self._run_command(command)
        public_key = self._test_public_jwk(output)
        self.assertIsNotNone(public_key)


    def test_parse_private(self):
        """
        Test reading in the private key
        """
        command = "python tools/scitokens-admin-create-key --private-key=tests/simple_private_key.pem --pem-private"
        output = self._run_command(command)
        private_key = self._test_private(output)
        self.assertIsNotNone(private_key)

        # Test public key
        command = "python tools/scitokens-admin-create-key --private-key=tests/simple_private_key.pem --pem-public"
        output = self._run_command(command)
        public_key = self._test_public(output)
        self.assertIsNotNone(public_key)

        # Test public key
        command = "python tools/scitokens-admin-create-key --private-key=tests/simple_private_key.pem --jwks-private"
        output = self._run_command(command)
        private_key = self._test_private_jwk(output)
        self.assertIsNotNone(public_key)

        # Test public key
        command = "python tools/scitokens-admin-create-key --private-key=tests/simple_private_key.pem --jwks-public"
        output = self._run_command(command)
        public_key = self._test_public_jwk(output)
        self.assertIsNotNone(public_key)

    def test_parse_public(self):
        """
        Test reading in the public key
        """
        # Create a temporary public key from the private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        tmpfile = tempfile.NamedTemporaryFile(delete=False)

        tmpfile.write(pem)
        tmpfile.close()
        self.to_delete.append(tmpfile.name)

        # Test public key
        command = "python tools/scitokens-admin-create-key --public-key={} --pem-public".format(tmpfile.name)
        output = self._run_command(command)
        public_key = self._test_public(output)
        self.assertIsNotNone(public_key)

        # Test public key
        command = "python tools/scitokens-admin-create-key --public-key={} --jwks-public".format(tmpfile.name)
        output = self._run_command(command)
        public_key = self._test_public_jwk(output)
        self.assertIsNotNone(public_key)

    def tearDown(self):
        for file_delete in self.to_delete:
            os.remove(file_delete)
        self.to_delete = []
