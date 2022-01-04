extends RefCounted
class_name JWTAlgorithmBuilder


static func random_secret(length: int = 10) -> String:
    return Crypto.new().generate_random_bytes(length).get_string_from_utf8()


static func HSA1(secret: String) -> JWTAlgorithm:
    var algorithm: JWTAlgorithm = JWTAlgorithm.new()
    algorithm._secret = secret
    algorithm._alg = JWTAlgorithm.Type.HMAC1
    return algorithm


static func HS1(secret: String) -> JWTAlgorithm:
    return HSA1(secret)


static func HSA256(secret: String) -> JWTAlgorithm:
    var algorithm: JWTAlgorithm = JWTAlgorithm.new()
    algorithm._secret = secret
    algorithm._alg = JWTAlgorithm.Type.HMAC256
    return algorithm


static func HS256(secret: String) -> JWTAlgorithm:
    return HSA256(secret)


static func RSA256(public_key: CryptoKey, private_key: CryptoKey = CryptoKey.new()) -> JWTAlgorithm:
    var algorithm: JWTAlgorithm = JWTAlgorithm.new()
    algorithm._public_crypto = public_key
    algorithm._private_crypto = private_key
    algorithm._alg = JWTAlgorithm.Type.RSA256
    return algorithm


static func RS256(public_key: CryptoKey, private_key: CryptoKey) -> JWTAlgorithm:
    return RSA256(public_key, private_key)


static func sign(text: String, algorithm: JWTAlgorithm) -> PackedByteArray:
    return algorithm.sign(text)


static func verify(jwt: JWTDecoder, algorithm: JWTAlgorithm) -> bool:
    return algorithm.verify(jwt)
