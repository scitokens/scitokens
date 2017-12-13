"""
Sample test file for loading a token from command-line parameters.
"""

import scitokens
import sys


token = scitokens.SciToken.deserialize(sys.argv[1].encode())

for claim in token.claims():
    print(claim)

