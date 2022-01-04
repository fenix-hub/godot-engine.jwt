extends RefCounted
class_name JWT

static func create(algorithm: JWTAlgorithm = null, header_claims: Dictionary = {}, payload_claims: Dictionary = {}) -> JWTBuilder:
    return JWTBuilder.new(algorithm, header_claims, payload_claims)

static func decode(jwt: String) -> JWTDecoder:
    return JWTDecoder.new(jwt)

static func require(algorithm: JWTAlgorithm) -> JWTVerifierBuilder:
    return JWTVerifierBuilder.new(algorithm)
