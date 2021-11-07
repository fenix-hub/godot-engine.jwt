extends Reference
class_name JWTBuilder

var crypto: Crypto = Crypto.new()

var algorithm: JWTAlgorithm
var header_claims: Dictionary = { alg = "", typ = "JWT" }
var payload_claims: Dictionary
var secret: String

func _init(algorithm: JWTAlgorithm = null, header_claims: Dictionary = {}, payload_claims: Dictionary = {}):
    if algorithm != null: self.algorithm = algorithm
    if not header_claims.empty(): self.header_claims = header_claims
    if not payload_claims.empty(): self.payload_claims = payload_claims

func with_header(header_claims: Dictionary) -> JWTBuilder:
    self.header_claims = header_claims
    return self

func with_algorithm(algorithm: String) -> JWTBuilder:
    self.header_claims[JWTClaims.Public.ALGORITHM] = algorithm
    return self

func with_type(type: String) -> JWTBuilder:
    self.header_claims[JWTClaims.Public.TYPE] = type
    return self

func with_key_id(key_id: String) -> JWTBuilder:
    self.header_claims[JWTClaims.Public.KEY_ID] = key_id
    return self

func with_issuer(issuer: String) -> JWTBuilder:
    add_claim(JWTClaims.Public.ISSUER, issuer)
    return self

func with_subject(subject: String) -> JWTBuilder:
    add_claim(JWTClaims.Public.SUBJECT, subject)
    return self

func with_audience(audience: PoolStringArray) -> JWTBuilder:
    add_claim(JWTClaims.Public.AUDIENCE, audience)
    return self

# Expires At in UNIX time (OS.get_unix_time())
func with_expires_at(expires_at: int) -> JWTBuilder:
    add_claim(JWTClaims.Public.EXPRIES_AT, expires_at)
    return self

# Not Before in UNIX time (OS.get_unix_time())
func with_not_before(not_before: int) -> JWTBuilder:
    add_claim(JWTClaims.Public.NOT_BEFORE, not_before)
    return self

# Issued At in UNIX time (OS.get_unix_time())
func with_issued_at(issued_at: int) -> JWTBuilder:
    add_claim(JWTClaims.Public.ISSUED_AT, issued_at)
    return self

func with_jwt_id(jwt_id: String) -> JWTBuilder:
    self.header_claims[JWTClaims.Public.JWT_ID] = jwt_id
    return self

func with_claim(name: String, value) -> JWTBuilder:
    add_claim(name, str(value))
    return self

func with_payload(payload_claims: Dictionary) -> JWTBuilder:
    for claim in payload_claims.keys():
        add_claim(claim, payload_claims[claim])
    return self

func sign(algorithm: JWTAlgorithm = null) -> String:
    if algorithm != null: self.algorithm = algorithm
    assert(algorithm != null, "Can't sign a JWT without an Algorithm")
    with_algorithm(algorithm.get_name())
    var header: String = JWTUtils.base64URL_encode(JSON.print(self.header_claims).to_utf8())
    var payload: String = JWTUtils.base64URL_encode(JSON.print(self.payload_claims).to_utf8())
    var signature_bytes: PoolByteArray = crypto.hmac_digest(self.algorithm._hash, self.algorithm._secret.to_utf8(), (header+"."+payload).to_utf8())
    var signature: String = JWTUtils.base64_encode(signature_bytes)
    return "%s.%s.%s" % [header, payload, signature]

func add_claim(name: String, value) -> void:
    match typeof(value):
        TYPE_ARRAY, TYPE_STRING_ARRAY: 
            if value.size() == 0 : 
                self.payload_claims.erase(name)
                return
        TYPE_STRING: 
            if value.length() == 0: 
                self.payload_claims.erase(name)
                return
        _:  
            if value == null:
                self.payload_claims.erase(name)
                return
    self.payload_claims[name] = value
