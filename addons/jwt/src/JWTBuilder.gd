extends JWTBaseBuilder
class_name JWTBuilder

var crypto: Crypto = Crypto.new()

var algorithm: JWTAlgorithm
var header_claims: Dictionary = { alg = "", typ = "JWT" }
var payload_claims: Dictionary
var secret: String

func _init(algorithm_param: JWTAlgorithm = null, header_claims_param: Dictionary = {}, payload_claims_param: Dictionary = {}):
    if not header_claims_param.is_empty(): self.header_claims = header_claims_param
    if not payload_claims_param.is_empty(): self.payload_claims = payload_claims_param
    if algorithm_param != null:
        self.algorithm = algorithm_param
        self.header_claims.alg = self.algorithm.get_name()

func add_claim(name: String, value) -> void:
    match typeof(value):
        TYPE_ARRAY, TYPE_PACKED_STRING_ARRAY: 
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


func sign(algorithm: JWTAlgorithm = null) -> String:
    if algorithm != null: self.algorithm = algorithm
    assert(algorithm != null, "Can't sign a JWT without an Algorithm")
    with_algorithm(algorithm.get_name())
    var header_serializer : JSON = JSON.new()
    var header: String = JWTUtils.base64URL_encode(header_serializer.stringify(self.header_claims).to_utf8_buffer())
    var payload_serializer : JSON = JSON.new()
    var payload: String = JWTUtils.base64URL_encode(payload_serializer.stringify(self.payload_claims).to_utf8_buffer())
    var signature_bytes: PackedByteArray = algorithm.sign(header+"."+payload)
    var signature: String = JWTUtils.base64URL_encode(signature_bytes)
    return "%s.%s.%s" % [header, payload, signature]
