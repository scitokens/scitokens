
"""
Install file for SciTokens project.
"""

import os.path
import re

import setuptools


def find_version(path, varname="__version__"):
    """Parse the version metadata variable in the given file.
    """
    with open(path, 'r') as fobj:
        version_file = fobj.read()
    version_match = re.search(
        r"^{0} = ['\"]([^'\"]*)['\"]".format(varname),
        version_file,
        re.M,
    )
    if version_match:
        return version_match.group(1)
    raise RuntimeError("Unable to find version string.")


setuptools.setup(name="scitokens",
                 version=find_version(os.path.join("src", "scitokens", "__init__.py")),
                 description="SciToken reference implementation library",
                 author_email="team@scitokens.org",
                 author="Brian Bockelman",
                 url="https://scitokens.org",
                 package_dir={"": "src"},
                 packages=["scitokens", "scitokens.tools", "scitokens.utils"],
                 entry_points={"console_scripts": [
                     "scitokens-admin-create-key=scitokens.tools.admin_create_key:main",
                     "scitokens-admin-create-token=scitokens.tools.admin_create_token:main",
                 ]},
                 install_requires=['cryptography',
                                   'PyJWT>=2.0.0',
                                   'six'],
                )
