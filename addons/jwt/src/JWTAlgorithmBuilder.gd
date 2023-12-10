class_name JWTAlgorithmBuilder
extends RefCounted


static func random_secret(length: int = 10) -> String:
	return Crypto.new().generate_random_bytes(length).get_string_from_utf8()


static func HSA1(secret: String) -> JWTAlgorithm:
	push_warning(
		"`JWTAlgorithmBuilder.HSA1()` is deprecated, use `JWTAlgorithm.HSA1.new()` instead"
	)
	return JWTAlgorithm.HSA1.new(secret)


static func HS1(secret: String) -> JWTAlgorithm:
	push_warning("`JWTAlgorithmBuilder.HS1()` is deprecated, use `JWTAlgorithm.HSA1.new()` instead")
	return HSA1(secret)


static func HSA256(secret: String) -> JWTAlgorithm:
	push_warning(
		"`JWTAlgorithmBuilder.HSA256()` is deprecated, use `JWTAlgorithm.HS256.new()` instead"
	)
	return JWTAlgorithm.HS256.new(secret)


static func HS256(secret: String) -> JWTAlgorithm:
	push_warning(
		"`JWTAlgorithmBuilder.HS256()` is deprecated, use `JWTAlgorithm.HSA256.new()` instead"
	)
	return HSA256(secret)


static func RSA256(public_key: CryptoKey, private_key: CryptoKey = CryptoKey.new()) -> JWTAlgorithm:
	push_warning(
		"`JWTAlgorithmBuilder.RSA256()` is deprecated, use `JWTAlgorithm.RS256.new()` instead"
	)
	return JWTAlgorithm.RS256.new(public_key, private_key)


static func RS256(public_key: CryptoKey, private_key: CryptoKey) -> JWTAlgorithm:
	push_warning(
		"`JWTAlgorithmBuilder.RS256()` is deprecated, use `JWTAlgorithm.RS256.new()` instead"
	)
	return RSA256(public_key, private_key)
