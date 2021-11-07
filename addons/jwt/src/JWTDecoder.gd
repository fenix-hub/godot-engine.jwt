extends Reference
class_name JWTDecoder

var parts: Array = []
var header_claims: Dictionary = {}
var payload_claims: Dictionary = {}

func _init(jwt: String):
    self.parts = jwt.split(".")
    var header: String = JWTUtils.base64URL_decode(self.parts[0])
    var payload: String = JWTUtils.base64URL_decode(self.parts[1])
    self.header_claims = JSON.parse(header).result
    self.payload_claims = JSON.parse(payload).result


func get_algorithm() -> String:
    return self.header_claims[JWTClaims.Public.ALGORITHM]

func get_type() -> String:
    return self.header_claims[JWTClaims.Public.TYPE]

func get_content_type() -> String:
    return self.header_claims[JWTClaims.Public.CONTENT_TYPE]

func get_key_id() -> String:
    return self.header_claims[JWTClaims.Public.KEY_ID]

func get_header_claim(name: String):
    return self.header_claims[name]

func get_header_claims() -> Dictionary:
    return self.header_claims

func get_issuer() -> String:
    return self.payload_claims[JWTClaims.Public.ISSUER]

func get_subject() -> String:
    return self.payload_claims[JWTClaims.Public.SUBJECT]

func get_audience() -> PoolStringArray:
    return self.payload_claims[JWTClaims.Public.AUDIENCE]

func get_expires_at() -> int:
    return self.payload_claims[JWTClaims.Public.EXPRIES_AT]

func get_not_before() -> int:
    return self.payload_claims[JWTClaims.Public.NOT_BEFORE]

func get_issued_at() -> int:
    return self.payload_claims[JWTClaims.Public.ISSUED_AT]

func get_id() -> String:
    return self.payload_claims[JWTClaims.Public.JWT_ID]

func get_claim(name: String):
    return self.payload_claims[name]

func get_claims() -> Dictionary:
    return self.payload_claims

func get_header() -> String:
    return self.parts[0]

func get_payload() -> String:
    return self.parts[1]

func get_signature() -> String:
    return self.parts[2]

func get_token() -> String:
    return ("%s.%s.%s" % parts)
