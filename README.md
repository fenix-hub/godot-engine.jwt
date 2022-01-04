# Godot Engine GDScript JWT  
JSON Web Token library for Godot Engine written in GDScript 

[Godot 3.x](https://github.com/fenix-hub/godot-engine.jwt) - [Godot 4.x](https://github.com/fenix-hub/godot-engine.jwt/tree/main-godot4)

## Create HS256 JWT
```gdscript
var secret: String = JWTAlgorithmBuilder.random_secret(5)
var jwt_algorithm: JWTAlgorithm = JWTAlgorithmBuilder.HS256(secret)
var jwt_builder: JWTBuilder = JWT.create() \
.with_expires_at(OS.get_unix_time()) \
.with_issuer("Godot") \
.with_claim("id","someid")
var jwt: String = jwt_builder.sign(jwt_algorithm)
```

## Verify HS256 JWT
```gdscript
var jwt: String = "<a jwt>"
var secret: String = "<your secret token>"
var jwt_algorithm: JWTAlgorithm = JWTAlgorithmBuilder.HS256(secret)
var jwt_verifier: JWTVerifier = JWT.require(jwt_algorithm) \
    .with_claim("my-claim","my-value") \
    .build() # Reusable Verifier
if jwt_verifier.verify(jwt) == JWTVerifier.JWTExceptions.OK :
	print("Verified!")
else:
	print(jwt_verifier.exception)
```

## Create RS256 JWT
```gdscript
var private_key : CryptoKey = crypto.generate_rsa(4096)
var public_key : CryptoKey = CryptoKey.new()
public_key.load_from_string(private_key.save_to_string(true))

var jwt_algorithm: JWTAlgorithm = JWTAlgorithmBuilder.RS256(public_key, private_key)
var jwt_builder: JWTBuilder = JWT.create() \
    .with_expires_at(OS.get_unix_time()) \
    .with_issuer("Godot") \
    .with_claim("id","someid")
var jwt: String = jwt_builder.sign(jwt_algorithm)
```

## Verify RS256 JWT
```gdscript
var private_key: CryptoKey = CryptoKey.new()
var public_key: CryptoKey = CryptoKey.new()
private_key.load_from_string("<your private key PEM string>", false)
public_key.load_from_string("<your public key PEM string>", true)

var jwt: String = "<a jwt>"
var jwt_algorithm: JWTAlgorithm = JWTAlgorithmBuilder.RS256(public_key)
var jwt_verifier: JWTVerifier = JWT.require(jwt_algorithm) \
    .with_claim("id","someid") \
    .build() # Reusable Verifier
if jwt_verifier.verify(jwt) == JWTVerifier.JWTExceptions.OK :
	print("Verified!")
else:
	print(jwt_verifier.exception)
```

## Decode JWT
```gdscript
var jwt: String = "<a jwt>"
var jwt_decoder: JWTDecoder = JWT.decode(jwt)
# Get the JWT as an Array
print("%s.%s.%s" % jwt_decoder.parts)
# Decode a specific part
print(JWTUtils.base64URL_decode(jwt_decoder.get_payload()))
```

### JWT Utils
```gdscript
JWTUtils.base64URL_encode(bytes: PoolByteArray) -> String
JWTUtils.base64URL_decode(string: String) -> PoolByteArray
```

#### Supported Algorithms
- [x] HS1 (HMAC with SHA1)
- [x] HS256 (HMAC with SHA256)
- [x] RS256 (RSA with SHA256)