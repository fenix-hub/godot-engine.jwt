# Godot Engine GDScript JWT  
JSON Web Token library for Godot Engine written in GDScript 

## Create JWT
```gdscript
var secret: String = "<your secret token>"
var jwt_algorithm: JWTAlgorithm = JWTAlgorithm.new(HashingContext.HASH_SHA256, secret)
var jwt: String = JWT.create() \
.with_expires_at(OS.get_unix_time()) \
.with_issuer("Godot") \
.with_claim("id","someid").sign(jwt_algorithm)
print(jwt)
```

## Decode a JWT
```gdscript
var jwt: String = "<a jwt>"
var jwt_decoder : JWTDecoder = JWT.decode(jwt)
print("%s.%s.%s" % jwt_decoder.parts)
```

## Verify JWT
```gdscript
var jwt: String = "<a jwt>"
var secret: String = "<your secret token>"
var jwt_algorithm: JWTAlgorithm = JWTAlgorithm.new(HashingContext.HASH_SHA256, secret)
var jwt_verification: int = JWT.require(jwt_algorithm).verify(jwt)
if jwt_verification == JWTVerifier.Exceptions.OK :
	print("Verified!")
```

You can also verify a GDScript created JWT [here](https://jwt.io/)
