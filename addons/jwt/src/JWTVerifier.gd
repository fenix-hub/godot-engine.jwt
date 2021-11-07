extends Reference
class_name JWTVerifier

enum Exceptions {
    OK = 0,
    ALGORITHM_MISMATCHING,
    SIGNATURE_VERIFICATION,
    TOKEN_EXPIRED,
    INALID_CLAIM
   }

var claims: Dictionary
var algorithm: JWTAlgorithm
var jwt_decoder: JWTDecoder

func _init(algorithm: JWTAlgorithm):
    self.algorithm = algorithm

func verify_algorithm(jwt_decoder: JWTDecoder, algorithm: JWTAlgorithm) -> bool:
    return jwt_decoder.get_algorithm() == algorithm.get_name()

func verify_signature(jwt_decoder: JWTDecoder) -> bool:
    return algorithm.verify(jwt_decoder)

func assert_claim_present(jwt_claims: Dictionary, claims: Array) -> bool:
    return jwt_claims.has_all(claims)

func assert_claim_values(jwt_claims: Dictionary, claims: Dictionary) -> bool:
    for claim in claims.keys():
        if (
            jwt_claims.get(claim) == null or 
            jwt_claims.get(claim) == "" or 
            jwt_claims.get(claim) != claims[claim]
            ):
            return false
    return true


func verify(jwt: String) -> int:
    self.jwt_decoder = JWTDecoder.new(jwt)
    if not (verify_algorithm(self.jwt_decoder, algorithm)): return Exceptions.ALGORITHM_MISMATCHING
    if not (verify_signature(self.jwt_decoder)): return Exceptions.SIGNATURE_VERIFICATION
    if not (assert_claim_present(self.jwt_decoder.payload_claims, self.claims.keys())): return Exceptions.INVALID_CLAIM
    if not (assert_claim_values(self.jwt_decoder.payload_claims, self.claims)): return Exceptions.INALID_CLAIM
    return Exceptions.OK
