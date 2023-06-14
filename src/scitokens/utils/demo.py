"""
A module for retrieving a signed token corresponding to a specified payload.
"""

import json
import requests
import scitokens

def token(payload: dict):
    """
    Get a signed token for the given payload.

    :param dict payload: a dictionary specifying the claims
    :returns: an encoded token for the payload
    """
    data = json.dumps({'algorithm': "ES256", 'payload': payload})
    resp = requests.post("https://demo.scitokens.org/issue", data=data)
    return resp.text


def parsed_token(payload: dict):
    """
    Get a parsed token for the given payload.

    :param dict payload: a dictionary specifying the claims
    :returns: a SciToken object
    """
    token = scitokens.utils.demo.token(payload)
    return scitokens.SciToken.deserialize(token)