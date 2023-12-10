class_name JWTAlgorithm
extends RefCounted


func get_name() -> String:
	assert(false, "JWTAlgorithm subclasses must implement `get_name()`")
	return ""


func sign(_text: String) -> PackedByteArray:
	assert(false, "JWTAlgorithm subclasses must implement `sign()`")
	return []


func verify(_jwt: JWTDecoder) -> bool:
	assert(false, "JWTAlgorithm subclasses must implement `verify()`")
	return false


# TODO: HSA1 is not secure and should be removed
class HSA1:
	extends JWTAlgorithm
	var _secret: PackedByteArray

	func _init(secret: String):
		push_warning("HSA1 is not secure, and should not be used")
		self._secret = secret.to_utf8_buffer()

	func get_name() -> String:
		return "HSA1"

	func sign(text: String) -> PackedByteArray:
		var crypto := Crypto.new()
		return crypto.hmac_digest(HashingContext.HASH_SHA1, self._secret, text.to_utf8_buffer())

	func verify(jwt: JWTDecoder) -> bool:
		var payload: String = jwt.parts[0] + "." + jwt.parts[1]
		var signature_bytes := self.sign(payload)
		return jwt.parts[2] == JWTUtils.base64URL_encode(signature_bytes)


class HS256:
	extends JWTAlgorithm
	var _secret: PackedByteArray

	func get_name() -> String:
		return "HS256"

	func _init(secret: String):
		self._secret = secret.to_utf8_buffer()

	func sign(text: String) -> PackedByteArray:
		var crypto := Crypto.new()
		return crypto.hmac_digest(HashingContext.HASH_SHA256, self._secret, text.to_utf8_buffer())

	func verify(jwt: JWTDecoder) -> bool:
		var payload: String = jwt.parts[0] + "." + jwt.parts[1]
		var signature_bytes := self.sign(payload)
		return jwt.parts[2] == JWTUtils.base64URL_encode(signature_bytes)


class RS256:
	extends JWTAlgorithm

	var _public_key: CryptoKey
	var _private_key: CryptoKey

	func _init(public_key: CryptoKey, private_key := CryptoKey.new()):
		self._public_key = public_key
		self._private_key = private_key

	func get_name() -> String:
		return "RS256"

	func sign(text: String) -> PackedByteArray:
		var crypto := Crypto.new()
		return crypto.sign(HashingContext.HASH_SHA256, text.sha256_buffer(), self._private_key)

	func verify(jwt: JWTDecoder) -> bool:
		var crypto := Crypto.new()
		var payload: PackedByteArray = (jwt.parts[0] + "." + jwt.parts[1]).sha256_buffer()
		var signature: PackedByteArray = JWTUtils.base64URL_decode(jwt.parts[2])
		return crypto.verify(HashingContext.HASH_SHA256, payload, signature, self._public_key)
