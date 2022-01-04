extends RefCounted
class_name JWTDecoder

var parts: Array = []
var header_claims: Dictionary = {}
var payload_claims: Dictionary = {}

func _init(jwt: String):
	self.parts = jwt.split(".")
	var header: PackedByteArray = JWTUtils.base64URL_decode(self.parts[0])
	var payload: PackedByteArray = JWTUtils.base64URL_decode(self.parts[1])
	self.header_claims = _parse_json(header.get_string_from_utf8())
	self.payload_claims = _parse_json(payload.get_string_from_utf8())

func _parse_json(field) -> Dictionary:
	var parse_result = JSON.new()
	if parse_result.parse(field) != OK:
		return {}
	return parse_result.get_data()

func get_algorithm() -> String:
	return self.header_claims.get(JWTClaims.Public.ALGORITHM, "null")

func get_type() -> String:
	return self.header_claims.get(JWTClaims.Public.TYPE, "null")

func get_content_type() -> String:
	return self.header_claims.get(JWTClaims.Public.CONTENT_TYPE, "null")

func get_key_id() -> String:
	return self.header_claims.get(JWTClaims.Public.KEY_ID, "null")

func get_header_claim(name: String):
	return self.header_claims.get(name, null)

func get_header_claims() -> Dictionary:
	return self.header_claims

func get_issuer() -> String:
	return self.payload_claims.get(JWTClaims.Public.ISSUER, "null")

func get_subject() -> String:
	return self.payload_claims.get(JWTClaims.Public.SUBJECT, "null")

func get_audience() -> PackedByteArray:
	return self.payload_claims.get(JWTClaims.Public.AUDIENCE, "null")

func get_expires_at() -> int:
	return self.payload_claims.get(JWTClaims.Public.EXPRIES_AT, -1)

func get_not_before() -> int:
	return self.payload_claims.get(JWTClaims.Public.NOT_BEFORE, -1)

func get_issued_at() -> int:
	return self.payload_claims.get(JWTClaims.Public.ISSUED_AT, -1)

func get_id() -> String:
	return self.payload_claims.get(JWTClaims.Public.JWT_ID, "null")

func get_claim(name: String):
	return self.payload_claims.get(name, "null")

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
