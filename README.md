# Godot Engine GDScript JWT  
JSON Web Token library for Godot Engine written in GDScript 

## Create JWT
```gdscript
	var secret: String = "<your secret token>"
    var jwt_algorithm: JWTAlgorithm = JWTAlgorithm.new(HashingContext.HASH_SHA256, secret)
    var jwt_builder: JWTBuilder = JWT.create() \
	.with_expires_at(OS.get_unix_time()) \
	.with_issuer("Godot") \
    .with_claim("id","someid")
	var jwt: String = jwt_builder.sign(jwt_algorithm)
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

## Verify JWT
```gdscript
	var jwt: String = "<a jwt>"
	var secret: String = "<your secret token>"
    var jwt_algorithm: JWTAlgorithm = JWTAlgorithm.new(HashingContext.HASH_SHA256, secret)
	var jwt_verifier: JWTVerifier = JWT.require(jwt_algorithm) \
	.with_claim("my-claim","my-value") \
	.build() # Reusable Verifier
	if jwt_verifier.verify(jwt) == JWTVerifier.Exceptions.OK :
		print("Verified!")
	else:
		print(jwt_verifier.exception)
```

### JWT Utils
```gdscript
	JWTUtils.base64URL_encode(bytes: PoolByteArray) -> String
	JWTUtils.base64URL_decode(string: String) -> String
```