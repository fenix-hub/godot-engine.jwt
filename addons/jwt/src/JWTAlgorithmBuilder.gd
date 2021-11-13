extends Reference
class_name JWTAlgorithmBuilder

static func random_secret(length: int = 10) -> String:
    return Crypto.new().generate_random_bytes(10).get_string_from_utf8()

static func HSA1(secret: String) -> JWTAlgorithm:
    var algorithm: JWTAlgorithm = JWTAlgorithm.new()
    algorithm._secret = secret
    algorithm._hash = JWTAlgorithm.Type.HMAC1
    return algorithm

static func HSA256(secret: String) -> JWTAlgorithm:
    var algorithm: JWTAlgorithm = JWTAlgorithm.new()
    algorithm._secret = secret
    algorithm._hash = JWTAlgorithm.Type.HMAC256
    return algorithm

static func RSA256(public_key: CryptoKey, private_key: CryptoKey) -> JWTAlgorithm:
    var algorithm: JWTAlgorithm = JWTAlgorithm.new()
    algorithm._public_crypto = public_key
    algorithm._private_crypto = private_key
    return algorithm

static func sign(text: String, algorithm: JWTAlgorithm) -> PoolByteArray:
    return algorithm.sign(text)

static func verify(jwt: JWTDecoder, algorithm: JWTAlgorithm) -> bool:
    return algorithm.verify(jwt)
