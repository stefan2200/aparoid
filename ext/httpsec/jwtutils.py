"""
Tool for checking, decoding and maybe cracking JWT tokens
"""
import jwt


def get_jwt(encoded_string):
    """
    Dis a JWT?
    :param encoded_string:
    :return:
    """
    try:
        header = jwt.get_unverified_header(encoded_string)
        body = jwt.decode(encoded_string, options={"verify_signature": False})
    except jwt.exceptions.InvalidTokenError:
        return None
    alg = header.get("alg", "HS256")

    check_key_security = try_default_secrets(encoded_string, alg)

    jwt_result = {
        "header": header,
        "body": body,
        "guessable_key": check_key_security
    }
    return jwt_result


def try_default_secrets(encoded_string, algorithm):
    """
    Check if it can be decoded using a default key
    Also includes the ALGO since peepz might swap the params
    :param encoded_string:
    :param algorithm:
    :return:
    """
    default_keys = ["", "secret", "admin", "secure", "key", algorithm]
    for default_key in default_keys:
        try:
            result = jwt.decode(encoded_string, default_key, algorithms=algorithm)
            if result:
                return default_key
        except jwt.exceptions.InvalidSignatureError:
            continue
        except jwt.exceptions.DecodeError:
            continue
    return None
