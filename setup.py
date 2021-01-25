
"""
Install file for SciTokens project.
"""

import setuptools

setuptools.setup(name="scitokens",
                 version="1.3.1",
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
                                   'PyJWT',
                                   'six'],
                )
