extends RefCounted
class_name JWTUtils

static func base64URL_encode(input: PackedByteArray) -> String:
    return Marshalls.raw_to_base64(input).replacen("+","-").replacen("/","_").replacen("=","")

static func base64URL_decode(input: String) -> PackedByteArray:
    match (input.length() % 4):
        2: input += "=="
        3: input += "="
    return Marshalls.base64_to_raw(input.replacen("_","/").replacen("-","+"))
