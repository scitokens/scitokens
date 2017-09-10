"""
Sample test file for loading a token from command-line parameters.
"""

import scitokens
import sys


scitokens.SciToken.deserialize(sys.argv[1])

