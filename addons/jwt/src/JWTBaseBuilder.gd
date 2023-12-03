extends RefCounted
class_name JWTBaseBuilder

func with_header(header_claims: Dictionary) -> JWTBaseBuilder:
    self.header_claims = header_claims
    return self

func with_algorithm(algorithm: String) -> JWTBaseBuilder:
    self.header_claims[JWTClaims.Public.ALGORITHM] = algorithm
    return self

func with_type(type: String) -> JWTBaseBuilder:
    self.header_claims[JWTClaims.Public.TYPE] = type
    return self

func with_key_id(key_id: String) -> JWTBaseBuilder:
    self.header_claims[JWTClaims.Public.KEY_ID] = key_id
    return self

func with_issuer(issuer: String) -> JWTBaseBuilder:
    add_claim(JWTClaims.Public.ISSUER, issuer)
    return self

func with_subject(subject: String) -> JWTBaseBuilder:
    add_claim(JWTClaims.Public.SUBJECT, subject)
    return self

func with_audience(audience: PackedStringArray) -> JWTBaseBuilder:
    add_claim(JWTClaims.Public.AUDIENCE, audience)
    return self

# Expires At in UNIX time (Time.get_unix_time_from_system())
func with_expires_at(expires_at: int) -> JWTBaseBuilder:
    add_claim(JWTClaims.Public.EXPIRES_AT, expires_at)
    return self

# Not Before in UNIX time (Time.get_unix_time_from_system())
func with_not_before(not_before: int) -> JWTBaseBuilder:
    add_claim(JWTClaims.Public.NOT_BEFORE, not_before)
    return self

# Issued At in UNIX time (Time.get_unix_time_from_system())
func with_issued_at(issued_at: int) -> JWTBaseBuilder:
    add_claim(JWTClaims.Public.ISSUED_AT, issued_at)
    return self

func with_jwt_id(jwt_id: String) -> JWTBaseBuilder:
    self.header_claims[JWTClaims.Public.JWT_ID] = jwt_id
    return self

func with_claim(name: String, value) -> JWTBaseBuilder:
    add_claim(name, str(value))
    return self

func with_payload(claims: Dictionary) -> JWTBaseBuilder:
    for claim in claims.keys():
        add_claim(claim, claims[claim])
    return self

func add_claim(claim_name: String, claim_value) -> void:
    return
