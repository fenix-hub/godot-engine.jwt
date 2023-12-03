extends RefCounted
class_name JWTVerifier

enum JWTExceptions {
    OK,
    INVALID_HEADER,
    INVALID_PAYLOAD,
    ALGORITHM_MISMATCHING,
    INVALID_SIGNATURE,
    TOKEN_EXPIRED,
    CLAIM_NOT_VALID
   }

var jwt_decoder: JWTDecoder
var algorithm: JWTAlgorithm
var claims: Dictionary
var clock: int
var exception: String

func _init(algorithm: JWTAlgorithm, claims: Dictionary, clock: int):
    self.algorithm = algorithm
    self.claims = claims
    self.clock = clock

func verify_algorithm(jwt_decoder: JWTDecoder, algorithm: JWTAlgorithm) -> bool:
    self.exception = "The provided Algorithm doesn't match the one defined in the JWT's Header."
    return jwt_decoder.get_algorithm() == algorithm.get_name()

func verify_signature(jwt_decoder: JWTDecoder) -> bool:
    self.exception = "The provided Algorithm doesn't match the one used to sign the JWT."
    return algorithm.verify(jwt_decoder)

func verify_claim_values(jwt_decoder: JWTDecoder, expected_claims: Dictionary) -> bool:
    for claim in expected_claims.keys(): 
        match claim:
            JWTClaims.Public.EXPIRES_AT:
                if not assert_valid_date_claim(jwt_decoder.get_expires_at(), expected_claims.get(claim), true):
                    self.exception = "The Token has expired on %s." % Time.get_datetime_string_from_unix_time(jwt_decoder.get_expires_at())
                    return false
            JWTClaims.Public.ISSUED_AT:
                if not assert_valid_date_claim(jwt_decoder.get_issued_at(), expected_claims.get(claim), false):
                    self.exception = "The Token can't be used before %s." % Time.get_datetime_string_from_unix_time(jwt_decoder.get_expires_at())
                    return false
            JWTClaims.Public.NOT_BEFORE:
                if not assert_valid_date_claim(jwt_decoder.get_not_before(), expected_claims.get(claim), false):
                    self.exception = "The Token can't be used before %s." % Time.get_datetime_string_from_unix_time(jwt_decoder.get_expires_at())
                    return false
            JWTClaims.Public.ISSUER:
                if not jwt_decoder.get_issuer() == expected_claims.get(claim):
                    self.exception = "The Claim 'iss' value doesn't match the required issuer."
                    return false
            JWTClaims.Public.JWT_ID:
                if not jwt_decoder.get_id() == expected_claims.get(claim):
                    self.exception = "The Claim '%s' value doesn't match the required one." % claim
                    return false
            JWTClaims.Public.SUBJECT:
                if not jwt_decoder.get_subject() == expected_claims.get(claim):
                    self.exception = "The Claim '%s' value doesn't match the required one." % claim
                    return false
            _:
                if not assert_claim_present(jwt_decoder, claim): 
                    self.exception = "The Claim '%s' is not present in the JWT." % claim
                    return false
                if not assert_claim_value(jwt_decoder, claim): 
                    self.exception = "The Claim '%s' value doesn't match the required one." % claim
                    return false
    return true

func assert_claim_present(jwt_decoder: JWTDecoder, claim: String) -> bool:
    return jwt_decoder.get_claims().has(claim)

func assert_claim_value(jwt_decoder: JWTDecoder, claim: String) -> bool:
    var valid_value: bool = -1
    match typeof(jwt_decoder.get_claims().get(claim)):
        TYPE_STRING: valid_value = (jwt_decoder.get_claims().get(claim) != "" and jwt_decoder.get_claims().get(claim) != "null")
        TYPE_INT: valid_value = (jwt_decoder.get_claims().get(claim) >= 0)
    return (jwt_decoder.get_claims().get(claim) != null and valid_value and jwt_decoder.get_claims().get(claim) == self.claims.get(claim))

func assert_valid_date_claim(date: int, leeway: int, should_be_future: bool) -> bool:
    if date == null: return true
    if should_be_future: return (self.clock - leeway) < date
    else: return (self.clock + leeway) > date

func assert_valid_header(jwt_decoder: JWTDecoder) -> bool:
    self.exception = "The header is empty or invalid."
    return not jwt_decoder.header_claims.is_empty()    

func assert_valid_payload(jwt_decoder: JWTDecoder) -> bool:
    self.exception = "The payload is empty or invalid."
    return not jwt_decoder.payload_claims.is_empty()

func verify(jwt: String) -> JWTExceptions:
    self.jwt_decoder = JWTDecoder.new(jwt)
    if not assert_valid_header(self.jwt_decoder): return JWTExceptions.INVALID_HEADER
    if not assert_valid_payload(self.jwt_decoder): return JWTExceptions.INVALID_PAYLOAD 
    if not verify_algorithm(self.jwt_decoder, algorithm): return JWTExceptions.ALGORITHM_MISMATCHING
    if not verify_signature(self.jwt_decoder): return JWTExceptions.INVALID_SIGNATURE
    if not verify_claim_values(self.jwt_decoder, self.claims): return JWTExceptions.CLAIM_NOT_VALID
    self.exception = ""
    return JWTExceptions.OK
