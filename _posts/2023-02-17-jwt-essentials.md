---
title: "JWT Essentials"
permalink: /post/jwt-essentials
layout: default
tags: JWT JWE authentication authorization security session claims JSON-Web-Token 
is_series: true
series_title: "Web Security"
series_number: 4
---

JWT tokens are used for communicating information between different applications and services, with properties that enable the receiver to certify the information in the JWT is authentic and has not be tampered with.

We will explain their implementation here, as they are a necessary part of OIDC authorization, which we will cover later.

JWT tokens themselves are simple to construct, consisting of three parts:

1. The header is a JSON object specifying the type of token and the algorithm used to sign the token, proving its authenticity:

	```json
	{
	  "alg": "HS256",
	  "typ": "JWT"
	}
	```

2. The payload, a JSON object containing the relevant information being transfered. 

	The JSON object can contain standardized fields such as `sub`, which usually means an identifier corresponding to the principal subject of the token, such as a user ID, and `exp`, which means the date and time after which the JWT is no longer valid. 

	Custom, 'private' fields with data only relevant to the ecosystem the JWT was created for can also be included:

	```json
	{
	  "sub": "1234567890",
	  "username": "John Doe",
	  "exp": 1713394800
	}
	```

3. The signature, a unique ID generated using:
	
	i. The algorithm specified by `alg`  
	ii. A secret key known only by the communicating parties  
	iii. A string created from base64Url encoding the header and payload and concatenating them with a dot (.)  
	
	For our example, and using the secret key 'secret', this looks like this:

	Header in base64Url: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9`

	Payload in base64Url: `eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJKb2huIERvZSIsImV4cCI6MTcxMzM5NDgwMH0`

	Signature: 

	```
	HMACSHA256(
		eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJKb2huIERvZSIsImV4cCI6MTcxMzM5NDgwMH0,
		secret
	) 
	```

	`= kl594WAxLmLh6vff2ytJ5hxjLBe4nmyt533MB2yOSsc`
	
	
***

Our signed JWT is then:

`eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJKb2huIERvZSIsImV4cCI6MTcxMzM5NDgwMH0.kl594WAxLmLh6vff2ytJ5hxjLBe4nmyt533MB2yOSsc`

i.e. [Header in base64Url].[Payload in base64Url].[Signature]

#### JWT Advantages

By including the signature, any party with the secret that receives the JWT can recreate the signature and compare it to the JWT's signature - if they match, the party can be confident that the Header and Payload information is authentic and has not been tampered with.

JWTs can also use asymmetric signing algorithms that utilize a public/private key pair. The private key is still used to create the signature and kept secret by the server, but the public key can be published openly and used by any party to verify the authenticity of the JWT claims.


JWTs can be used for authentication and authorization in web applications in a similar manner to session tokens, but are particularly useful for Single Page Applications with no server backend -
the user can authenticate with an Identity Provider, which will provide a JWT that includes the user's identity information.

Even if issued by a backend server, they can record the user's authentication state, meaning the server doesn't have to keep track of each user's session - this can be advantageous for scaling large applications.

They also can be used to share the user's authentication state and other identity details with different services on different domains - enabled by sharing the same signing key with each service.

#### JWT Challenges

JWTs are stateless by design, storing user state information themselves instead of relying on a server-side session. With no dependence on a particular server or issuing authority for their validity, changing any user state can be difficult. This is especially challenging if the JWT is trusted and read by multiple services. 

For example, if JWTs need to be revoked for certain users, it would mean maintaining a blacklist of revoked tokens, and sharing this across all resources that trust the JWT. This rather defeats the purpose and advantages of using stateless tokens to represent user state.

Assuming a JWT received by an application is required for future requests, it needs to be persisted in the browser session. The optimal storage location then depends on the application requirements. 

If the JWT needs to be forwarded to different domains than its origin, it may be appropriate to store as a cookie, as these can be automatically forwarded to other domains, depending on the cookie attributes set.

The best JWT storage option is really application dependent, so this table summarizes the advantages and tradeoffs each storage mechanism offers:

| JWT Storage Option                     | JWT Automatically forwarded to other domains | Protection against XSS attacks | Protection against CSRF attacks | JWT Content can be read by app | JWT Can be forwarded to any domain using JS | Persists across different Browser Sessions |
| -------------------------------------- | ---------------------------------------- | ------------------------------ | ------------------------------- | ------------------------------ | ------------------------------------------- | ------------------------------------------- |
| Cookie with HttpOnly                  | Depends on SameSite/Domain attributes  | Yes                            | Depends on SameSite/Domain attributes  | No                             | No                                          | Depends if MaxAge/Expires set              |
| Cookie with SameSite Strict/Lax       | No                                       | No                             | Yes                             | Yes                            | Yes                                         | Depends if MaxAge/Expires set              |
| Cookie with no attribute restrictions | Yes                                      | No                             | No                              | Yes                            | Yes                                         | Depends if MaxAge/Expires set              |
| SessionStorage                         | No                                       | No                             | N/A (Not sent with requests)    | Yes                            | Yes                                         | No                                          |
| LocalStorage                           | No                                       | No                             | N/A (Not sent with requests)    | Yes                            | Yes                                         | Yes                                         |


### Avoid Adding Sensitive Information to JWTs

There are several reasons to avoid including sensitive information in the JWT:

1. The payload information is not encrypted, and can be read by anyone with access to it

2. JWTs can be exposed in multiple places depending on the application - XSS attacks could read JWTs stored in sessionStorage, localStorage or some cookie types.

3. If used as part of a larger service ecosystem, JWTs may end up being sent in many HTTP requests, increasing their exposure to interception.

To securely store sensitive information in JWTs, a related technology called [JWE tokens](https://datatracker.ietf.org/doc/html/rfc7516) can be used to encrypt the JWT payload. 

JWEs add additional complexity to a JWTs alone, requiring more resources to generate and verify, and resulting in larger tokens than standard JWTs. However, the benefit of preventing unauthorized access to the JWT payload often justifies the additional resources required. 

