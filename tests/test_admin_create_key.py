"""
Test the admin-create-key tool
"""

import os
import sys
import unittest

# Codacy has issues with subprocess, but this is only in the tests!
import subprocess # nosec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
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

    tool = "-m scitokens.tools.admin_create_key"
    to_delete = []

    def setUp(self):
        os.environ['PYTHONPATH'] = os.pathsep.join(sys.path)
        self.to_delete = []

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
    def _test_ec_public_jwk(key):
        """
        Attempt to read in the key into a key object
        """
        keys = json.loads(key.decode('utf-8'))
        public_key_numbers = ec.EllipticCurvePublicNumbers(
            long_from_bytes(keys['keys'][0]['x']),
            long_from_bytes(keys['keys'][0]['y']),
            ec.SECP256R1()
        )
        return public_key_numbers.public_key(default_backend())

    @staticmethod
    def _test_public_jwk(key):
        """
        Attempt to read in the key into a key object
        """
        keys = json.loads(key.decode('utf-8'))
        public_key_numbers = rsa.RSAPublicNumbers(
            long_from_bytes(keys['keys'][0]['e']),
            long_from_bytes(keys['keys'][0]['n'])
        )
        return public_key_numbers.public_key(default_backend())


    @staticmethod
    def _test_ec_private_jwk(key):
        """
        Attempt to read in the key into a private key object
        """
        keys = json.loads(key.decode('utf-8'))
        public_key_numbers = ec.EllipticCurvePublicNumbers(
            long_from_bytes(keys['keys'][0]['x']),
            long_from_bytes(keys['keys'][0]['y']),
            ec.SECP256R1()
        )
        private_key_numbers = ec.EllipticCurvePrivateNumbers(
            long_from_bytes(keys['keys'][0]['d']),
            public_key_numbers
        )
        return private_key_numbers.private_key(default_backend())

    @staticmethod
    def _test_private_jwk(key):
        """
        Attempt to read in the key into a private key object
        """
        keys = json.loads(key.decode('utf-8'))
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
        # Bandit tests in codacy doesn't like shell=True, but this is suppose to
        # test the user actually running the command from the shell, so keep
        # shell=True is necessary.
        command_run = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) # nosec
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
        command = "{} {} --create-keys --pem-private".format(sys.executable, self.tool)
        output = self._run_command(command)
        private_key = self._test_private(output)
        self.assertIsNotNone(private_key)

        # Test public key
        command = "{} {} --create-keys --pem-public".format(sys.executable, self.tool)
        output = self._run_command(command)
        public_key = self._test_public(output)
        self.assertIsNotNone(public_key)

        # Test public key
        command = "{} {} --create-keys --jwks-private".format(sys.executable, self.tool)
        output = self._run_command(command)
        private_key = self._test_private_jwk(output)
        self.assertIsNotNone(public_key)

        # Test public key
        command = "{} {} --create-keys --jwks-public".format(sys.executable, self.tool)
        output = self._run_command(command)
        public_key = self._test_public_jwk(output)
        self.assertIsNotNone(public_key)

    def test_ec_create(self):
        """
        Test the key creation
        """
        command = "{} {} --ec --create-keys --pem-private".format(sys.executable, self.tool)
        output = self._run_command(command)
        private_key = self._test_private(output)
        self.assertIsNotNone(private_key)

        # Test public key
        command = "{} {} --ec --create-keys --pem-public".format(sys.executable, self.tool)
        output = self._run_command(command)
        public_key = self._test_public(output)
        self.assertIsNotNone(public_key)

        # Test public key
        command = "{} {} --ec --create-keys --jwks-private".format(sys.executable, self.tool)
        output = self._run_command(command)
        private_key = self._test_ec_private_jwk(output)
        self.assertIsNotNone(public_key)

        # Test public key
        command = "{} {} --ec --create-keys --jwks-public".format(sys.executable, self.tool)
        output = self._run_command(command)
        public_key = self._test_ec_public_jwk(output)
        self.assertIsNotNone(public_key)


    def test_parse_private(self):
        """
        Test reading in the private key
        """
        command = "{} {} --private-key=tests/simple_private_key.pem --pem-private".format(sys.executable, self.tool)
        output = self._run_command(command)
        private_key = self._test_private(output)
        self.assertIsNotNone(private_key)

        # Test public key
        command = "{} {} --private-key=tests/simple_private_key.pem --pem-public".format(sys.executable, self.tool)
        output = self._run_command(command)
        public_key = self._test_public(output)
        self.assertIsNotNone(public_key)

        # Test public key
        command = "{} {} --private-key=tests/simple_private_key.pem --jwks-private".format(sys.executable, self.tool)
        output = self._run_command(command)
        private_key = self._test_private_jwk(output)
        self.assertIsNotNone(public_key)

        # Test public key
        command = "{} {} --private-key=tests/simple_private_key.pem --jwks-public".format(sys.executable, self.tool)
        output = self._run_command(command)
        public_key = self._test_public_jwk(output)
        self.assertIsNotNone(public_key)

    def test_ec_parse_private(self):
        """
        Test reading in the private key
        """
        command = "{} {} --ec --private-key=tests/simple_ec_private_key.pem --pem-private".format(sys.executable, self.tool)
        output = self._run_command(command)
        private_key = self._test_private(output)
        self.assertIsNotNone(private_key)

        # Test public key
        command = "{} {} --ec --private-key=tests/simple_ec_private_key.pem --pem-public".format(sys.executable, self.tool)
        output = self._run_command(command)
        public_key = self._test_public(output)
        self.assertIsNotNone(public_key)

        # Test public key
        command = "{} {} --ec --private-key=tests/simple_ec_private_key.pem --jwks-private".format(sys.executable, self.tool)
        output = self._run_command(command)
        private_key = self._test_ec_private_jwk(output)
        self.assertIsNotNone(public_key)

        # Test public key
        command = "{} {} --ec --private-key=tests/simple_ec_private_key.pem --jwks-public".format(sys.executable, self.tool)
        output = self._run_command(command)
        public_key = self._test_ec_public_jwk(output)
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
        command = "{} {} --public-key={} --pem-public".format(sys.executable, self.tool, tmpfile.name)
        output = self._run_command(command)
        public_key = self._test_public(output)
        self.assertIsNotNone(public_key)

        # Test public key
        command = "{} {} --public-key={} --jwks-public".format(sys.executable, self.tool, tmpfile.name)
        output = self._run_command(command)
        public_key = self._test_public_jwk(output)
        self.assertIsNotNone(public_key)

    def test_ec_parse_public(self):
        """
        Test reading in the public key
        """
        # Create a temporary public key from the private key
        private_key = ec.generate_private_key(
            ec.SECP256R1(),
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
        command = "{} {} --ec --public-key={} --pem-public".format(sys.executable, self.tool, tmpfile.name)
        output = self._run_command(command)
        public_key = self._test_public(output)
        self.assertIsNotNone(public_key)

        # Test public key
        command = "{} {} --ec --public-key={} --jwks-public".format(sys.executable, self.tool, tmpfile.name)
        output = self._run_command(command)
        public_key = self._test_ec_public_jwk(output)
        self.assertIsNotNone(public_key)

    def tearDown(self):
        for file_delete in self.to_delete:
            os.remove(file_delete)
        self.to_delete = []
