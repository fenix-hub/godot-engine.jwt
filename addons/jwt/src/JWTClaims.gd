extends RefCounted
class_name JWTClaims


class Public:
    #   Header
    const ALGORITHM: String = "alg"
    const CONTENT_TYPE: String = "cty"
    const TYPE: String = "typ" 
    const KEY_ID: String = "kid"

    #   Payload
    const ISSUER: String = "iss"
    const SUBJECT: String = "sub"
    const EXPIRES_AT: String = "exp"
    const NOT_BEFORE: String = "nbf"
    const ISSUED_AT: String = "iat"
    const JWT_ID: String = "jti"
    const AUDIENCE: String = "aud"
