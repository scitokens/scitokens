
"""
Install file for SciTokens project.
"""

import setuptools

setuptools.setup(name="scitokens",
                 version="0.1.5",
                 description="SciToken reference implementation library",
                 author_email="team@scitokens.org",
                 author="Brian Bockelman",
                 url="https://scitokens.org",
                 package_dir={"": "src"},
                 packages=["scitokens"],
                 install_requires=['cryptography',
                                   'PyJWT',
                                   'urltools'],
                )
