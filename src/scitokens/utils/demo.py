import json
import requests

# Specify an algorithm for signature
# ES256 = Elliptic Curve with SHA-256
# getToken will return a signed token with the payload
# rename to token
def getToken(payload: dict):
    data = json.dumps({'algorithm': "ES256", 'payload': payload})
    resp = requests.post("https://demo.scitokens.org/issue", data=data)
    return resp.text

