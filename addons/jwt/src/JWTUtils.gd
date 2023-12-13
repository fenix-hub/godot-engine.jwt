class_name JWTUtils
extends RefCounted


static func urlsafe_b64encode(input: PackedByteArray) -> String:
	return Marshalls.raw_to_base64(input).replacen("+", "-").replacen("/", "_").replacen("=", "")


static func urlsafe_b64decode(input: String) -> PackedByteArray:
	match input.length() % 4:
		2:
			input += "=="
		3:
			input += "="
	return Marshalls.base64_to_raw(input.replacen("_", "/").replacen("-", "+"))
