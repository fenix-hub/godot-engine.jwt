extends Reference
class_name JWT

static func create() -> JWTBuilder:
    return JWTBuilder.new()

static func decode(jwt: String) -> JWTDecoder:
    return JWTDecoder.new(jwt)

static func require(algorithm: JWTAlgorithm) -> JWTVerifierBuilder:
    return JWTVerifierBuilder.new(algorithm)
