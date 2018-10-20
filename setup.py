
"""
Install file for SciTokens project.
"""

import setuptools

setuptools.setup(name="scitokens",
                 version="1.2.1",
                 description="SciToken reference implementation library",
                 author_email="team@scitokens.org",
                 author="Brian Bockelman",
                 url="https://scitokens.org",
                 package_dir={"": "src"},
                 packages=["scitokens", "scitokens.utils"],
                 scripts=['tools/scitokens-admin-create-token',
                          'tools/scitokens-admin-create-key'],
                 install_requires=['cryptography',
                                   'PyJWT',
                                   'six'],
                )
