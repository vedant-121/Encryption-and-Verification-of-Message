def rsa_encrypt(e:int, n:int, msg: str):
     # Convert Plain Text -> Cypher Text
    cypher_text = ''
    # C = (P ^ e) % n
    for ch in msg:
        # convert the Character to ascii (ord)
        ch = ord(ch)
        # convert the calculated value to Characters(chr)
        cypher_text += chr((ch ** e) % n)
    return cypher_text


def rsa_decrypt(d:int, n:int, cipher_t: str):
    # Convert Plain Text -> Cypher Text
    plain_text = ''
    # P = (C ^ d) % n
    for ch in cipher_t:
        # convert it to ascii
        ch = ord(ch)
        plain_text += chr((ch ** d) % n)

    return plain_text

