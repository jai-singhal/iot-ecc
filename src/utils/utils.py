from Crypto.Hash import HMAC, SHA256

def createHMAC(msg:list):
    secret = msg[0]
    assert isinstance(secret, bytes)

    h = HMAC.new(secret, digestmod=SHA256)
    for m in msg[1:]:
        assert isinstance(m, bytes)
        h.update(m)
    return h.hexdigest()