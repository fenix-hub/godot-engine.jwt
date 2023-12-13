class_name JWTBuilder
extends JWTBaseBuilder

var crypto: Crypto = Crypto.new()

var _algorithm: JWTAlgorithm
var _header_claims: Dictionary = {alg = "", typ = "JWT"}
var _payload_claims: Dictionary


func _init(
	algorithm_param: JWTAlgorithm = null,
	header_claims_param: Dictionary = {},
	payload_claims_param: Dictionary = {}
):
	if not header_claims_param.is_empty():
		self._header_claims = header_claims_param
	if not payload_claims_param.is_empty():
		self._payload_claims = payload_claims_param
	if algorithm_param != null:
		self._algorithm = algorithm_param
		self._header_claims.alg = self._algorithm.get_name()


func add_claim(name: String, value) -> void:
	match typeof(value):
		TYPE_ARRAY, TYPE_PACKED_STRING_ARRAY:
			if value.size() == 0:
				self._payload_claims.erase(name)
				return
		TYPE_STRING:
			if value.length() == 0:
				self._payload_claims.erase(name)
				return
		_:
			if value == null:
				self._payload_claims.erase(name)
				return
	self._payload_claims[name] = value


func sign(algorithm: JWTAlgorithm = null) -> String:
	if algorithm != null:
		self._algorithm = algorithm
	assert(algorithm != null, "Can't sign a JWT without an Algorithm")
	with_algorithm(algorithm.get_name())
	var header: String = JWTUtils.urlsafe_b64encode(
		JSON.stringify(self._header_claims).to_utf8_buffer()
	)
	var payload: String = JWTUtils.urlsafe_b64encode(
		JSON.stringify(self._payload_claims).to_utf8_buffer()
	)
	var signature_bytes: PackedByteArray = algorithm.sign(header + "." + payload)
	var signature: String = JWTUtils.urlsafe_b64encode(signature_bytes)
	return "%s.%s.%s" % [header, payload, signature]
