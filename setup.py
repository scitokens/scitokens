
"""
Install file for SciTokens project.
"""

import setuptools

setuptools.setup(name="scitokens",
                 version="0.1.6",
                 description="SciToken reference implementation library",
                 author_email="team@scitokens.org",
                 author="Brian Bockelman",
                 url="https://scitokens.org",
                 package_dir={"": "src"},
                 packages=["scitokens"],
                 scripts=['tools/scitokens-admin-create-token',
                          'tools/scitokens-admin-create-key'],
                 install_requires=['cryptography',
                                   'PyJWT'],
                )
