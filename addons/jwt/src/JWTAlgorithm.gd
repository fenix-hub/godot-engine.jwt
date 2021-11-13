extends Reference
class_name JWTAlgorithm

var _hash: int = -1
var _secret: String = ""
var _name: String = ""

var crypto: Crypto = Crypto.new()

func _init(hashing: int = -1, secret: String = ""):
    self._hash = hashing
    self._secret = secret
    self._name = return_name(self._hash)

func return_name(hashing: int) -> String:
    match hashing:
        HashingContext.HASH_SHA256: return "HS256"
    return ""

func HMAC256(secret: String) -> JWTAlgorithm:
    self._hash = HashingContext.HASH_SHA256
    self._secret = secret
    self._name = "HS256"
    return self

func get_name() -> String:
    return _name

func verify(jwt: JWTDecoder) -> bool:
    var signature_bytes: PoolByteArray = []
    match self._hash:
        HashingContext.HASH_SHA256:
                signature_bytes = crypto.hmac_digest(self._hash, self._secret.to_utf8(), (jwt.parts[0]+"."+jwt.parts[1]).to_utf8())
    return jwt.parts[2] == JWTUtils.base64URL_encode(signature_bytes)
