from S2C09 import is_pkcs7_padded


def main():
    """I had implemented the is_pkcs_padded method before, so I will just reuse it here."""
    assert is_pkcs7_padded(b'ICE ICE BABY\x04\x04\x04\x04') is True
    assert is_pkcs7_padded(b'ICE ICE BABY\x05\x05\x05\x05') is False
    assert is_pkcs7_padded(b'ICE ICE BABY\x01\x02\x03\x04') is False
    assert is_pkcs7_padded(b'ICE ICE BABY') is False


if __name__ == '__main__':
    main()
