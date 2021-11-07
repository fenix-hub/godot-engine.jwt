extends Control

var secret: String = "secret"

func _ready():
    var jwt_algorithm: JWTAlgorithm = JWTAlgorithm.new(HashingContext.HASH_SHA256, secret)
    var jwt_string: String = JWT.create().with_expires_at(OS.get_unix_time()).\
    with_claim("id","someid").sign(jwt_algorithm)
    print(jwt_string)
    var jwtdecoder : JWTDecoder = JWT.decode(jwt_string)
    var jwt_verifier: JWTVerifier = JWT.require(jwt_algorithm)
    print(jwt_verifier.verify(jwt_string) == JWTVerifier.Exceptions.OK)
