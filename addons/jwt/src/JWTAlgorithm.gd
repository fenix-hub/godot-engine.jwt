extends Reference
class_name JWTAlgorithm

enum Type {
    HMAC1,
    HMAC256,
    RSA256
}

var _hash: int = -1
var _secret: String = ""

var crypto: Crypto = Crypto.new()
var _public_crypto: CryptoKey = CryptoKey.new()
var _private_crypto: CryptoKey = CryptoKey.new()

func get_name() -> String:
    match _hash:
        Type.HMAC1: return "HSA1"
        Type.HMAC256: return "HSA256"
        Type.RSA256: return "RSA256"
        _: return ""

func sign(text: String) -> PoolByteArray:
    var signature_bytes: PoolByteArray = []
    match self._hash:
        Type.HMAC1:
            signature_bytes = self.crypto.hmac_digest(HashingContext.HASH_SHA1, self._secret.to_utf8(), text.to_utf8())
        Type.HMAC256:
            signature_bytes = self.crypto.hmac_digest(HashingContext.HASH_SHA256, self._secret.to_utf8(), text.to_utf8())
        Type.RSA256:
            signature_bytes = self.crypto.encrypt(self._private_crypto, text.to_utf8())
    return signature_bytes

func verify(jwt: JWTDecoder) -> bool:
    var signature_bytes: PoolByteArray = []
    match self._hash:
        Type.HMAC1:
            signature_bytes = crypto.hmac_digest(HashingContext.HASH_SHA1, self._secret.to_utf8(), (jwt.parts[0]+"."+jwt.parts[1]).to_utf8())
        Type.HMAC256:
            signature_bytes = crypto.hmac_digest(HashingContext.HASH_SHA256, self._secret.to_utf8(), (jwt.parts[0]+"."+jwt.parts[1]).to_utf8())
        Type.RSA256:
            signature_bytes = self.crypto.decrypt(self._public_crypto, (jwt.parts[0]+"."+jwt.parts[1]).to_utf8())
    return jwt.parts[2] == JWTUtils.base64URL_encode(signature_bytes)
