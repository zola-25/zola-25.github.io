---
title: "Web Authentication"
permalink: /post/web-authentication
layout: default
tags: authentication basic jwt session HTTP HTTPS privacy
---

### HTTP Basic Access Authentication

Basic Access Authentication is probably the simplest authentication scheme to implement.

When an unauthenticated user tries to access a restricted resource, the server responds with a 401 Unauthorized status and a WWW-Authenticate response header field, with the header value 'Basic realm="[Name given to resource user is trying to access]"'.

The realm here is required and serves as an identifier for the part of the site the user is trying to access - for example there could be other realms that serve different resources that the user may, or may not, be authorized to view.

This triggers a browser popup (similar to a popup produced by the alert() javascript function), allowing them to submit a username and password:

<img width="457" alt="image" src="https://user-images.githubusercontent.com/29863888/232664769-3208f8ba-fc09-457e-9c4e-dd871b846edf.png">

The browser then combines these into a single string with a colon separator, e.g. user1:pAssWord123, encodes to Base64, and prepends "Basic ". This is then set as the Authorization request header value and sent to the server.

The server then decodes the Base64 credentials, and validates that they match the user credentials stored on the server. If so, the user is permitted access and the restricted content is returned:

<img width="273" alt="image" src="https://user-images.githubusercontent.com/29863888/232664967-79e3c8a7-936a-4e3b-b08f-92835b127cc3.png">

Otherwise a 401 or similar access denied response can be returned by the server.


A simple ASP.NET Core example demonstrates the server logic, using the minimal API: 

```csharp

var app = WebApplication.Create(args);

string validUsername = "user1";
string validPassword = "password123";


app.MapGet("/", (HttpContext httpContext) =>
{
    if (!HasAuthorizationHeader(httpContext))
    {

		httpContext.Response.Headers.Add(HeaderNames.WWWAuthenticate,
			new StringValues(new[] { "Basic", "realm=\"User Visible Realm\", charset=\"UTF-8\"" }));
		return Results.Unauthorized();

    }

    var authorizationHeaders = httpContext.Request.Headers[HeaderNames.Authorization];
    if (authorizationHeaders.Count != 1)
    {
        return Results.Content("Expecting one Authorization header", statusCode: StatusCodes.Status401Unauthorized);
    }

    var authorizationHeader = authorizationHeaders[0]!;

    if (!authorizationHeader.StartsWith("Basic "))
    {
        return Results.Content("'Basic ' authorization scheme expected", statusCode: StatusCodes.Status401Unauthorized);
    }

    var encodedCredentials = authorizationHeader.Replace("Basic ", String.Empty);

    var decodedBytes = Convert.FromBase64String(encodedCredentials);
    var credentials = Encoding.UTF8.GetString(decodedBytes).Split(":");
    var username = credentials[0];
    var password = credentials[1];

    if (username == validUsername && password == validPassword)
    {
        return Results.Text("User Authorized! <br/> <br/> <b>The Permitted content authorized for user</b>", "text/html");
    }

    return Results.Content("Invalid credentials", statusCode: StatusCodes.Status401Unauthorized);

});

app.Run();

```

Note the additional charset="UTF-8" returned in the WWWAuthenticate response header is used to specify the acceptable encoding for the username and password.

#### Security implications of Basic Access Authentication

Given that the user's credentials are transmitted unencrypted to the server, they should be transmitted through HTTPS instead of HTTP.

As long as the browser application remains open, these credentials are sent with every subsequent request to the protected resource, which is a potential security vulnerability as it only requires one interception to have access to the client's credentials.

The credentials are stored in the browser's process memory and usually inaccessible to both users and developers, hence why they are lost when the browser application is closed. 

However, some modern browsers may prompt the user to store the credentials in their built-in password storage, as they would when a user first enters credentials into a more typical form-based login page.

## Storing User Credentials Securely on the Server with Password Hashing

Real world applications that implement their own authentication process (e.g. user accounts with sign-in forms) must ensure user passwords are secured, and unreadable in the event the server is compromised.

Password hashing enables a user to verify a password provided by the user without the app's server ever having stored the password. The server instead stores a hash of the password, which is computationally infeasibile to translate back to the user's plaintext password - assuming the hashing process correctly implemented with a strong hashing algorithm.

### Implementation [^note on detail]

#### Application setup

Let's assume we've created a web app requiring user authentication.

The authentication is implemented by the application. We're not outsourcing authentication to an Identiy Provider in this example, since we're demonstrating password security itself.

The user first creates an account by submitting their email and password securely in plaintext. 

The server typically creates an entry in its database for the user and stores their email, usually for a variety of verification and recovery proposes, but for this example it's only required along with their password to prove the the user is authentic when they make a login request.

#### Simple Hashing Implementation

The password itself is not saved. Instead it is input to a type of algorithm called a [Cryptographic Hash Function](https://en.wikipedia.org/wiki/Cryptographic_hash_function) (CHF) which then returns its corresponding 'hash' value as a sequence of bits of fixed length, the length dependent on the CHF used - typically 256 bits. 

For readability and convenience this is often converted to its base64 equivalent, resulting in a fixed length string of 44 characters, with no discerable pattern or structure. 

We can demonstrate the hash created for the password "Password123" using the SHA-256 hash function:

```pwsh
$inputString = "Password123"

$sha256 = [System.Security.Cryptography.SHA256]::Create()
$bytes = [System.Text.Encoding]::UTF8.GetBytes($inputString)
$hashBytes = $sha256.ComputeHash($bytes)

$base64String = [System.Convert]::ToBase64String($hashBytes)

$binaryString = [System.Text.StringBuilder]::new()
foreach ($byte in $hashBytes) {
    $binaryString.Append([Convert]::ToString($byte, 2).PadLeft(8, '0'))
}

Write-Output "`nHash of $inputString in 256 bit binary: $binaryString"

Write-Output "`nHash of $inputString in base64: $base64String"
```

We get:

```
0000000010001100011100000011100100101110001110101011111110111101000011111010010001111011101111000010111011011001011010101010100110011011110101001001111000010101100101110010011111111100101110100000111100101110011010101011111010110011101010011101011000000001
```

or in base64:

```
AIxwOS46v70PpHu8LtlqqZvUnhWXJ/y6Dy5qvrOp1gE=
```

This hash is a simple fixed length string of different characters, with no discerable pattern or structure, and has the appearence of being randomly generated, although it is not. 

If the password differed only slightly, perhaps by one character, the CHF would produce a hash with a completely different set of characters - this is a property all CHFs have and is called the [avalanche effect](https://en.wikipedia.org/wiki/Avalanche_effect).

For example, if our password is instead "Password12**4**", the SHA-256 hash in base64 becomes:

```
UawBynkjzYgRe3aBNDuR0h0/a65csNlJYnCZ/AL0ubw=
```

CHFs are designed to ensure a 'uniform distribution' of hash value character string combinations. As long as we use a secure, industry-proven CHF that creates sufficently large hash values - 256 bits is considered large enough for most use cases - each possible hash value is equally possible of being the one computed for a password.

256 bit hash values means $2^256$ possible hash values, each one having a probability of $1/2^256$ of being chosen, which is [effectively impossible to guess](https://crypto.stackexchange.com/a/45310).

It's important to note that this doesn't imply randomness in the CHF - the algorithm is deterministic and for a known plaintext password, exactly one of the $2^256$ possible hashes will have a 100% probability of being generated.

Storing passwords as hashes is intended to ensure the plaintext password is unknowable when stored on the server. When a user wants to authenticate with the application, for example through a sign-in form, they send their password as plaintext to the app's server. The server converts it into its unique hash and compares it to the existing hash stored for that user. Matching hashes proves the password matches the one the provided in the sign-up process, so the user is considered authentic, and the sign-in is authorized.

#### Simple Hashing Vulnerabilities

The previous example demonstrates a rudimentary approach to securing passwords through hashing. When hashing was introduced as a security measure, over time vulnerabilities in the process became evident:

1) **Pre-computing hashes**

   Because each password always generates the same hash, they are vulnerable to exploits where an attacker attacker pre-computes and stores hash/password combinations. The number of possible password/hash combinations makes it unrealistic to generate all conceivable combinations, but optimizations that trade increased password lookup time for storage size can be used instead to make such attacks feasible, such as ([rainbow tables](https://en.wikipedia.org/wiki/Rainbow_table#Precomputed_hash_chains)).


2) **Collision attacks**

   Some hashing algorithms have been proven to be at risk of generating the same hash for two different passwords, allowing an attacker gain access by finding a string with a hash that matches that of an existing user's password.

   Older hashing algorithms such as MD5 and SHA-1 have been demonstrated to be have this vulnerability and are now considered insecure for use as password security. Modern hashing algorithms like SHA-256 are much more resistant to collision attacks, though no hashing algorithm can ever be entirely immune.

### Secure Cryptographic Hash Function

Modern password hashing is uses Secure Cryptographic Hash Functions. These Secure CHFs have advantages over traditional CHFs:

1. **Eliminating collision attacks**<br/>
   <br/>
   The likelihood of hash collisions is so low, it becomes computationally infeasible to identify a collision using modern technology, making Secure CHFs very resistant to collision attacks.

2. **Adaptability**<br/>
   <br/>
   Secure CHFs can allow the adjustment of the computational resources needed to derive a hash. This is designed to make the generation of vast amounts of password/hash combinations computationally impractical for an attacker, while ensuring the hash generation speed for legitimate purposes is practical.

3. **Mitigating against rainbow and dictionary attacks with password salting**<br/>
   <br/>
   A salt is a random value added to the password before hashing, which is then stored, unencrypted, with the resulting hash. For later password verification, the hash is recreated for comparison by including the salt as before.

   Password salting ensures:
   
   * Unique hashes for identical passwords  
     
     This prevents an attacker from identifying duplicate passwords in a database
     
   * Pre-computation attack protection  
     
     Pre-computation attacks and their variants are massively more resource and time-intensive, as an attacker must compute hashes for each possible salt-password combination, which is exponentially larger than for just passwords.

***

While there are CHFs that are secure against collision attacks, like SHA-256, only CHFs that provide all of the above advantages are considered 'Secure Cryptographic Hash Functions', making them suitable for modern-day password security. Such Secure CHFs include PBKDF2, bcrypt and PBKDF2. The ASP.NET Core Identity framework uses PBKDF2.

CHFs like SHA-256 are designed to be fast, and are used for other purposes than password hashing, whereas Secure CHFs are designed to be slow for attack prevention. 

Secure CHFs often use algorithms such as SHA-256 as a part of their algorithm.


#### Dictionary-attack Example with Salting and Computation Adjustment

Even in the event the user database is compromised, there are additional properties of the hashing process that can prevent an attacker from cracking the hashed passwords. 

First let's demonstrate dictionary attack on a compromised database. In a dictionary attack, the attacker has a large list of common, 'guessable' passwords. The database will include all password hashes along with each hash's unique salt that was used to generate it by the hashing function. 

If the attacker knows the hashing algorithm, they input a guessable password, along with one of the database's salts, and see if the resulting hash matches the hash in the database created from the salt.

The full attack involves attempting every guessable password with every database salt.

Some dictionary attacks attempt millions of common passwords. So if we consider the scenario where the attacker has one million guessable passwords, and a compromised database of 10000 hashes and salts, the attacker would run the hashing algorithm 10 billion times in an attempt to generate a hash that matched one in the database. If they found a match, they'd have found the genuine password that corresponded to that hash.

10 billion hash creations is obviously a lot, but the feasibility of such an attack depends on the execution time of the particular hash algorithm. Strong CHFs are designed to be computationally resource intensive, making them sufficiently slow, which helps mitigate against this kind of dictionary attack and other 'brute-force' methods. 

Ideally they are slow enough to mitigate these attacks but not so slow that their legitmate uses are affected, like fast credential verification for authentication, so typically these algorithms are configured to generate a hash in 0.1-1 seconds. 

In our dictionary attack example, a 0.5 second hash time would take 158 years to test all one million guessable passwords.

Once an algorithm's computational parameters have been set, they cannot be changed without changing the algorithm's hash outputs. So if an attacker changes the paramters to be much faster, so they can test a massive numbers of potential passwords as quickly as possible, the adjusted algorithm will just create different hashes than the unadultered algorithm that originally generated the hashes.


[^note on detail]: There's a lot of raw implementation here, expecially when it helps demonstrate a whole bunch of vulnerabilities, exploits, mitigations, an essential time-savers that a developer ever mixed-up in authentication might want to know about.

### Authentication with Session Cookies

This is a widely used, browser-based approach for website authentication.

It's also easy to understand and easy to implement a rudimentary version, without using any external libraries. However it has numerous security exploits without all precautions taken, or if misconfigured. For these reasons it is nearly always implemented on the server using proven third-party libaries, such as those available for .NET and PHP.

#### Session Cookie Authentication Steps:

1) A user submits their username and password through a traditional HTML <form>. Since these are plain, unencrypted values, the connection to the server should *always* be over HTTPS. The request should always be a POST request as the credentials will be stored in the HTTP body, instead of a GET request where the credentials will be appended to the request URL which is visible to anyone, even with HTTPS.

2) The server receives this request and validates the credentials. It then generates a unique, unguessable session ID using an [Cryptographically secure pseudorandom number generator](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator). This ID is then associated with the user in the server's memory or database.

3) The server then sends back the ID in the set-cookie header. Any further navigation around the site  sends the cookie back so the server knows the user is already authenticated and can track their actions across the site.

#### Security considerations

The session ID cookie should only contain the randomly generated session ID, and not any other user-specific information that could be obtained by attackers.

The HttpOnly attribute ensures no javascript can access the cookie - this can avoid malicious injected scripts accessing the session ID.

The SameSite attribute stops the session ID being sent in cross-site requests, and when the attribute value is set to Strict, ensures that the session ID can't be sent even on top-level navigations, such as clicking links or entering new URLs.

Similarly, if the Domain attribute is set on the cookie, the web browser will only send the cookie to the specified Domain and any subdomains of that root domain. However this can be a vulnerability if an attacker gains access to any subdomain of the root domain. For this reason it is recommended to avoid setting the Domain attribute on the session cookie, as the browser will then only send the cookie to the root domain.

The session ID cookie should only be sent over HTTPS - so it is appropriate to ensure all content delivered from the site domain, including images and files, are available over HTTPS only, as requests to these resources will also send the session ID cookie.

[HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) can be used to force the browser to ensure all subsequent requests to the site domain are made over HTTPS. A similar precaution is to ensure the session ID cookie always includes the Secure attribute, ensuring it is only sent over HTTPS.

The session ID cookie should not be set with Max-Age or Expires attributes, as these will save the cookie to the user's drive (assuming the lifetime is longer than their browser session). This is a vulnerability as it makes the session ID accessible to anything malicious running on the user's device.

#### Library-free implementation in ASP.NET Core

```csharp
public static class InMemoryDataStore
{
	public static readonly Dictionary<string, string> UserSessions = new();
	public static readonly Dictionary<string, string> UserCredentials = new() { { "user1", "password1" }, { "user2", "password2" } };
}

public class Credentials
{
	public string Username { get; set; }
	public string Password { get; set; }
}

public class HomeController : Controller
{
	[HttpGet]
	public IActionResult Index()
	{
		string? sessionId = HttpContext.Request.Cookies["sessionId"];
		bool isLoggedIn = sessionId != null && InMemoryDataStore.UserSessions.ContainsKey(sessionId);

		if (isLoggedIn)
		{
			var username = InMemoryDataStore.UserSessions[sessionId!];

			return Content($"Welcome {username}, you are authorized");
		}
		else
		{
			return RedirectToAction("Login");
		}
	}

	[HttpGet("Login")]
	public IActionResult Login()
	{
		return View();
	}

	[HttpPost("Login")]
	public IActionResult LoginSubmit([FromForm] Credentials credentials)
	{
		string username = credentials.Username;
		string password = credentials.Password;

		if (InMemoryDataStore.UserCredentials.ContainsKey(username) && InMemoryDataStore.UserCredentials[username] == password)
		{
			string sessionId = GenerateSessionId();
			InMemoryDataStore.UserSessions.Add(sessionId, username);
			
			HttpContext.Response.Cookies.Append("sessionId", sessionId, new CookieOptions()
			{
				Secure = true,
				HttpOnly = true,
				SameSite = SameSiteMode.Strict
			});

			return RedirectToAction("Index");
		}
		else
		{
			return Unauthorized("Invalid username or password. Please try again.");
		}
	}

	string GenerateSessionId()
	{
		byte[] randomBytes = RandomNumberGenerator.GetBytes(32);
		return Convert.ToBase64String(randomBytes);
	}
```
With the simple login form:

```html
<form method="post" asp-action="LoginSubmit">
	<label>
		Username:
		<input type="text" name="username" required>
	</label>
	<br>
	<label>
		Password:
		<input type="password" name="password" required>
	</label>
	<br>
	<button type="submit">Login</button>
</form>
```

#### Ensuring session ID invalidation

Session IDs should expire and be removed from server storage after a set period of time. This helps prevent scenarios where an authenticated user leaves their device with the browser still open, allowing another - potentally malicous - user to use the device to access sensitive content.

Additionally, sites should provide authenticated users with a logout mechanism that acts to remove or invalidates the session ID on the server.

## JWT-based authentication

JWT tokens are a method for communicating information between different applications and services that can be verified as authentic and untampered.

JWT tokens themselves are simple to construct, consisting of three parts:

1) The header, a JSON object specifying the type of token and the algorithm used to sign the token to prove its authenticity:

```json
{
  "alg": "HS256",
  "typ": "JWT"
}
```

2) The payload, a JSON object containing the relevant information being transfered. 

The JSON fields specified can contain standardized fields such as sub, which usually means an identifier corresponding to the principal subject of the token, such as a user ID, and exp, which means the date and time after which the JWT is no longer valid. 

Custom, 'private' fields with data only relevant to the ecosystem the JWT was created for can also be included.

```json
{
  "sub": "1234567890",
  "username": "John Doe",
  "exp": 1713394800
}
```

3) The signature, a unique ID created using the specified algorithm, a secret key and a string created from base64Url encoding the header and payload and concatenating them with a dot (.). For our example, and using the secret key 'secret', this looks like this:

Header in base64Url -> eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9

Payload in base64Url -> eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJKb2huIERvZSIsImV4cCI6MTcxMzM5NDgwMH0

Signature -> HMACSHA256(
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJKb2huIERvZSIsImV4cCI6MTcxMzM5NDgwMH0,
secret
) = kl594WAxLmLh6vff2ytJ5hxjLBe4nmyt533MB2yOSsc

Our signed JWT is then 

eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJKb2huIERvZSIsImV4cCI6MTcxMzM5NDgwMH0.kl594WAxLmLh6vff2ytJ5hxjLBe4nmyt533MB2yOSsc

i.e. [Header in base64Url].[Payload in base64Url].[Signature]

By including the signature, any party with the secret that receives the JWT can recreate the signature and compare it to the JWT's signature - if they match, the party can be confident the Header and Payload information is authentic and has not been tampered with.

JWTs can also use asymmetric signing algorithms that utilize a public/private key pair. The private key is still used to create the signature and kept secret by the server, but the public key can be published openly and used by any party to verify the authenticity of the JWT claims.

JWTs can be used for authentication and authorization in web applications in a similar manner to session tokens - after a user sends valid credentials to the server, the server creates and signs the JWT with any appropriate user identification and claims in the payload, and sends it back to the client. Subsequent client requests to the server include the JWT and the server identifies and verifies the user information in the payload and grants access.

One advantage of this flow is that the server does not have to maintain a list of session IDs active for each user - the only thing the server maintains is the secret used for verifying the JWT claims. 

The server can also include in the JWT information relevant to the user, rather than store all user details server side.

Despite these advantages, the use of JWT tokens for authorization still has some drawbacks when compared to session ID tokens: 


#### JWT payload is unencrypted

Since the payload information can be easily decoded, and is stored in the browser, sensitive information is vulnerable to being exposed even if the information cannot be tampered with without invalidating the JWT signature.

Instead of using JWTs to hold sensitive information, [JWE tokens](https://datatracker.ietf.org/doc/html/rfc7516) can be used to secure payload data. However they have a more complex implementation than JWTs, requiring more resources to generate and verify, and are much larger than standard JWTs.

#### JWTs need to be secured both in transit and at rest

Like session tokens, JWTs still need to be sent with every request, so should only be sent over HTTPS. Different security implications apply to how the JWT is sent and how it is stored on the browser. JWTs can be stored and sent as cookies, in which case the same security mechanisms should be applied to session ID cookies, such the [appropriate cookie attributes](#security-considerations) to prevent CSRF and other exploits.

Generally, a JWT should not be stored in local storage. Firstly, local storage on the hard drive is stored as plain text and can be read by any other process on the user's device. Secondly, local storage is vulnerable to being read by [XSS attacks](2022-06-01-browser-security-fundamentals.md#cross-site-scripting-xss)

JWTs can be also be stored in browser process memory, but this memory is lost when a tab or browser window is closed. Standardized authentication protocols can work around this limitation, which we will cover next.

### OAuth

#### Allowing third-party access to site functionality

For non-user driven sites that offer API interfaces for their functionality (for instance a site providing weather data), OAuth is likely unnecessary and just generating unique API keys for registered clients is easy to implement.

But for user-focused sites that wish to allow third-party apps to add extra functionality to their platform, these apps often need access to user data.

Before OAuth, these apps would often require the user's site credentials to function. This meant sharing credentials between the two parties. The security risks of this approach included:

1) Credentials being leaked
2) Inability for users to revoke access
3) Inability to control the user information available to client apps

OAuth was originally developed as a secure method allowing websites to share user-related data with third-party applications, without sharing user credentials.

Using the OAuth protocol, First-party websites can grant third-party apps limited access to resources, varying by the requirements of the third-party app, and allowing users to easily revoke access previously granted. 

These first-party websites are often widely used, established ecosytems (such as Microsoft and Google) that act as Identity Providers, although any site with user authentication can implement OAuth for third-party application access. 

In 2007 Twitter was the first major site to adopt OAuth for third-party applications accessing its API.

There are two major versions of the OAuth protocol, OAuth 1.0 and OAuth 2.0 (OAuth 1.0 was found to have major vulnerability and was quickly patched to become OAuth 1.0a, although the version IDs are usually used interchangeably.)


#### OAuth 1.0 flow

1) With OAuth 1.0, the process of registering a third-party application for access usually begins with the third-party app developer submitting details of their app's purpose and requirements for review by the first-party site. Once registered, the service-provider would provide the client app with a Consumer API Key and a Consumer Secret, stored on the client app's server. 

2) When a user wishes to authorize the client app, the client app requests a temporary ('request') token from the service provider via a server-to-server request. The request will include the Consumer Key, as well as several other parameters such as timestamp and a signature algorithm. Before the request is a signature is created from these parameter values and the Consumer Secret, and added to the request. Since the Consumer Secret is known by the service provider, it is used to verify the signature of the request is valid and so the request can be trusted.

3) With the client app's request trusted, a Request Token is and a Request Token Secret are sent back to the client app's server. The app server will then redirect the user to the service provider's authorization page, with the Request Token included in the redirect URL, along with a callback URL to the client app. The callback URL is where the service provider will send the user after they have authenticated and granted permissions to (authorized) the client app. Note the user only authenticates here, at the service provider - hence user credentials are not shared with the client app.

4) When the service provider redirects the user back to the client app's site, via the provided callback URL, the Request Token and a 'Verifier Token' are appended to the URL. The Request Token is necessary so that the client app maintains the state of OAuth process - in other words, because the app server was already sent the Request Token at the beginning of the user's auth process, it knows this particular user has completed authentication and authorization, especially necessary in the case where there may be multiple users authorizing at the same time. 

The Verifier Token is a random value generated by the service provider for each successful user authentication and authorizion. Since it is known only by the service provider and the client app, it is used in subsequent Access Token requests (step 5) as additional security, such as a case where the Request Token details have been compromised.

5) The client app's server then prepares a server-to-server request to the service provider to obtain an Access Token. The request will include the initial Request Token (to identify the current auth process), the Verifier Token (to prove user access was granted), the Consumer Key (to confirm the client app making the request), a signature method along with a signature created from the request parameters, the Consumer Secret and the Request Token Secret. The service provider knows the Consumer Secret and Request Token Secret, and verifies the signature based on the provided signature method. Once verified, a randomly generated Access Token and an Access Token Secret are sent back to the app server. The app server now has everything it needs to perform the actions authorized by the user.

6) The Access Token is used to identify the user along with the specific permissions granted to the client-app. When the service provider issues an access token, it associates it with the user that has granted permission. The Access Token Secret is used as an additional security measure to ensure the requests coming from the client app are authentic. As part of every request, the client app specifies a signature algorithm, and uses it to create a signature based on the Consumer Secret and Access Token Secret, along with the requests other parameters. Given the service provider knows the Consumer Secret and Access Token Secret, it can verify this signature to ensure the app request is authentic. 

Note that these signature verification methods prevents against interception ('man-in-the-middle' attacks) and subsequent user impersonation, since the Consumer Secret is never sent in any HTTP request/response in the OAuth 1.0 process, and the Access Token Secret is only sent once to the client app server to be used for proving request authenticity.

#### Drawbacks 

Find OAuth 1.0 confusing? Me too. Even in this outline of the OAuth 1.0 flow, I haven't covered full implementation details. The convoluted process of providing secure user authorization is one of a number of OAuth 1.0 drawbacks. Here are a few more:

1) Complexity - The number of requests, keys, secrets, signatures, and amount of cryptography involved means a developer implementation 'from scratch', without unwittingly introducing vulnerabilities, can be very difficult. Even apps using established OAuth libaries may still have vulnerabilities if misconfigured.

2) Secret security - OAuth 1.0 is mainly designed for server-based client apps, as most secrets required for requests need to be stored securely. While these secrets could be stored in the browser for Single Page Applications, or on mobile devices, these storage locations are at a greater risk of being compromised. 

3) Scalability adjustments - Details such as a user's assigned Access Token need to be stored at both the service provider's server and the app client's server - if either of these need to be scaled horizontally, typical accommodations need to be made to ensure all server nodes access consistent data.


## OAuth 2.0

OAuth 2.0 both improves and expands upon OAuth 1.0, with simpler authentication processes, and a modular approach that allows for additional use-cases besides  server-based client app authorization.

In fact, OAuth 2.0 offers several 'flows' that are appropriate for different scenarios:

1) Authorization Code Flow

Most similar to the OAuth 1.0 flow, used for server-based client applications, but easier to implement than OAuth 1.0.

2) Implict Flow (also called Implict Grant Flow)

Designed for applications that cannot fully secure the application-specific secret required for authorization (aka the 'client secret').

This includes Single Page Applications with zero server-side functionality, and native applications including mobile and desktop applications operating without a secure server backend.

Implict Flow issues Access Tokens directly after user authorization. Has significant security vulnerabilities and its use is [no longer recommended](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics-16#name-implicit-grant) by the IETF.

3) Authorization Code Flow with PKCE (Proof Key for Code Exchange)

The recommended alternative to Implicit Flow for applications unable to secure a client secret.

The flow is similar to the standard OAuth 2.0 Authorization Code Flow, *** link ***. It has many security benefits compared to Implicit Flow, such as limiting an Access Token's visibility and risk of interception; and ensuring an Access Token can only be received by the client app instance of the authenticated user.


4) Resource Owner Password Credentials (ROPC)

With ROPC, a user enters their credentials directly into the client app, which then forwards them in an API request to the authorization server for authentication. The authorization server then returns an Access Token for the requested resource.

It is generally not recommended for applications operating on the open internet, and goes against the main rationale of OAuth which is to enable authorization of third-party applications so they can access secured resources, without sharing credentials with them.

However an example use case for ROPC could be when a client application is highly trusted, and interacts with the authorization server within a closed network, such as a secure company intranet. 

4) Client Credentials Flow

This is generally used for server-to-server communication with no user requirement. 

A client application authenticates itself with the authorization server, and is sent an access token used to access the resources of another server. 

The client application should be server-based to store their credentials securely.

5) Device Authorization Flow

Device Authorization Flow is designed for authorizing client apps that run on a different device than one the user will use to interact with the authorization server.

A typical use case looks like:

1) A user has an existing account with a streaming service (e.g. Netflix).

2) They have a smart TV with the service's app installed.

3) They wish to authorize this app to use their account (essentially just authenticating with the app).

4) They could authenticate manually through the app, but the user interface on the TV is difficult to use, so instead they authenticate on a user-friendlier device such as their mobile device. Device Authorization Flow is the process that enables this.

A simplified version of the Device Authorization Flow process works as follows:

The streaming app is prompted by the user to authorize.

The streaming app sends a request to the authorization server to initiate the authorization process.

The authorization server:

1) Geneates a random device code to identify streaming app device being authorized.

2) Geneates a random user code identifying the authorization process being started.

3) Stores these together on the server temporarily, as they will be needed for later verification when the user completes authorization.

4) Sends the streaming app the URL the user must navigate to on their mobile device, including the user code, and the device code:

{
  "device_code": "DEVICE_CODE",
  "authorization_url": "https://authorization.streaming-service.com/user-auth-page?USER_CODE",
}


The device begins making polling requests to the authorization server in the background, asking if the device code has been authorized yet. 


The authorization URL can be rendered on the TV as a QR code, that the user can open on their mobile device. The authorization URL will be specific to the streaming service, it will open the streaming service's login page in the browser or the streaming service mobile app itself.  

When the user authenticates, or if they are already authenticated, they will simply be asked if they wish to authorize the device app to use their account.

When the user confirms, the authorization server looks up the device code for the user in its memory, verifies it matches the device code in the polling requests, and returns an Access Token to the streaming app. 

The Access Token then allows the streaming app access to the user's account.



### Authorization Code Flow

This is most similar to the OAuth 1.0 flow. It is appropriate for server-based client apps, that can securely store secrets received from an authentication provider.

1) First, like in OAuth 1.0, the third-party client app developers register the app with the service provider. 

During registration the app is assigned a 'client_id', a unique identifer for the app, and a 'client_secret', used for authenticating the app when requesting Access Tokens and should be kept confidential.

In addition, during registration a 'redirect_uri' must be provided, pointing to the client app that ensures the authorization server will send the user back to the genuine client app after user authorization.

Although only the 'client_secret' is strictly confidential, all of these app-specific values should be stored on the server as the server will use them to construct valid URLs that the browser will navigate to when the user authenticates with the authorization server and enables permissions for the client app, as described in step 2.

2) When a user wishes to authorize the client app, their browser is directed to the authorization server with a URL generated by the client server with the following query parameters:

'client_id' (the apps unique identifer provided by the service provider)

'response_type' - this is set to 'code' which indicates the app is initiating the Authorization Code Flow

'scope' - the list of permissions the client app is asking the user to authorize

'redirect_uri' - the uri of the client app that must match the one registered with the service provider.

'state' - a randomly value generated by the client server specifically for the authorization request and saved to the user's session. The state value is used to protect against CSRF attacks. 

A CSRF attack, by definition, tricks the user into initiating a request from a location outside of the genuine client site, such as from within an email or another site. Since the state value is generated for each user authentication session, when the same value is returned by the authorization server it confirms the response is for the same request that was initiated by the user.

While the client_id and redirect_uri also to some degree confirm to the authorization server that the request came from a valid source, they are at risk of being intercepted by an attacker and used to mimic an genuine authorization request. It is only when the client server compares the state value from the authorization response to the one it generated for the user session that the response can verified as genuine and the authorization flow can continue.

3) 

After the user successfully authenticates with the authorization server and authorizes the client app's requested permissions, the authorization server redirects the user's browser back to the client app via the redirect_uri, appending the 'scope' and 'code' as query parameters to the URL. The 'code' value is the temporary authorization code the client app will use to obtain an Access Token.

The client app's server then makes a POST request to a specific token exchange endpoint on the authorization server. 

The POST request contains the parameters:

'grant-type' - "authorization_code" to tell the authorization server this is the Authorization code flow

'code' - the temporary authorization code 

'redirect_uri' - as sent in the authorization request

'client_id' - the app's unique identifer

'client_secret' - the app's secret from the app's registration
 
These parameters should be sent as URL-encoded form data in the request body, to protect sensitive data, especially the 'client_secret' that must be kept confidential.

4) 

When the authorization server receives the POST request at the token exchange endpoint, it validates that the 'client_id', 'client_secret' and 'redirect_uri' match a registered app, and the 'code' - the temporary authorization code - has not expired and was issued for the app corresponding to the 'client_id' and 'client_secret'.

Assuming the validation is successful, the server sends a response back to the client app's server containing a JSON object with:

```json
{ 
	'access_token': <Access Token value>,
	'token_type': Bearer,
	'expires_in': <the number of seconds the token is valid>,
	'refresh_token': <optional, a Refresh Token used to obtain a new Access Token when the issued one expires>
}

This data stored on the server and associated with the user.

The app server can then make API requests to the service provider for permitted resources on behalf of the user, by including the header:

```
Authorization: Bearer <Access Token>
```

By making these requests from the server, the Access Token is not exposed to the user's browser and remains secure. 

5)

Refresh Tokens

To avoid requiring the user re-authorize when their Access Token expires, a client app can either:

1) Use Refresh Tokens to gain fresh Access Tokens - if Refresh Tokens are supported by the OAuth 2.0 implementation

2) Have very-long lifetime Access Tokens - but these are at a greater risk of being exposed since they are sent with every request. Also not all OAuth 2.0 implementations support Access Token revokation.

#### Obtaining fresh Access Tokens with a Refresh Token

Access Tokens expire when the 'expires_in' time, set in the JSON sent from the token exchange endpoint, is reached. It is often prudent to gain a fresh Access Token at a set time before this expiry is reached, to maintain app continuity for the user.

When a fresh Access Token is required, the client app server makes a POST request to the same token exchange endpoint on the authorization server that was called to in step 3) to gain the first Access Token.

The POST request should include in the request body, as URL-encoded form data:

'grant_type' - "refresh_token"

'refresh_token' - the Refresh Token from a secure store

'client_id' - the app's unique identifer

'client_secret' - the app's secret from a secure store

'scope' - the requested scopes, or omitted if the new Access Token is to have the same access as the expiring one

Assuming the request, along with the Refresh Token, is validated, the token exchange will typically respond with the JSON:

```json
{ 
	'access_token': <New Access Token value>,
	'token_type': Bearer,
	'expires_in': <the number of seconds the new token is valid>,
	"scope": <optional, a list of scopes the new token has access to, if new scopes were set in the refresh request>
	'refresh_token': <optional, an updated Refresh Token used to obtain the next Access Token when the updated one expires>
}
```

However the exact JSON contents may vary with the OAuth 2.0 implementation. Some implementations may issue a new Refresh Token each time, others may only ever require the original for refresh Access Token requests.

This data is then linked to the authorized user and the new Access Token used as before.



2) Client-Side Applications - Implicit flow vs Authorization Code Flow with PKCE

Client-side applications are generally considered less secure at storing sensitive information like client secrets. 

In the case of SPAs, source code is accessible, and browser tools make it easy to find secrets stored in the browser. They can be vulnerable to XSS attacks, allowing malicious scripts access to browser storage.

Mobile apps, while often running on platforms that do offer some mechanisms for secure storage, are still vulnerable when faced with a determined attacker armed with reverse-engineering and debugging tools. [Here's a comprehensive explanation](https://ivrodriguez.com/why-embedding-secrets-in-mobile-apps-is-not-a-good-idea/)

OAuth 2.0 has two flows designed specifically for client-side applications, Implicit Flow and Authorization Code Flow with PKCE. Implicit Flow is mostly regarded as an insecure implementation, and has been largely superseeded by the more secure Authorization Code Flow with PKCE.

However let's briefly examine Implicit Flow and it's vulnerabilities, and show how Authorization Code Flow with PKCE improves on it.

### Implicit Flow process

1) As with standard Authorization Code Flow, we register our app's details with a service provider, including a unique client_id and a redirect_uri that the authorization server will direct the user after authorization.

2) Authorization request construction

To authorize the client app, the app constructs a URL pointing to the authorization server, along with the query parameters:

'client_id' - the app's unique identifer

'scope' - the list of permissions the client app is asking the user to authorize

'redirect_uri' - the uri of the client app that must match the one registered with the service provider.

'state' - a randomly value generated by the client specifically for the authorization request and saved to the user's session. The state value is used to protect against CSRF attacks, explained in detail ******here******

'response_type' - token (indicating the client app wants to receive the Access Token directly)

When the user wishes to authorize the client app, this URL is opened in a new tab sending the authorization request as a GET request to the authorization server.

3) In the new tab displaying the authorization server's authentication screen, the user authenticates with their credentials and authorizes the app with its requested permissions (defined in the 'scope' query parameter).

4) After the user has granted authorization, the user is redirected back to the client app via the 'redirect_uri'. 

The Access Token, along with the standard OAuth token parameters such as expiry time, are included in the URL as part of the URL fragment:

https://my-spa.com/callback#access_token=akb982234huiwa&token_type=bearer&expires_in=3600&state=32fasq3q3qr

The Access Token and other parameters are sent as a URL fragment (everything after the #) because URL fragments aren't sent to the server. Even if our server does nothing except return the SPA content, it still may log or monitor requests, and this prevents the sensitive data being recorded in these logs. Browser caches also store URLs with query parameters. 
5) The SPA extracts the Access Token and other relevant parameters from the URL and stores them in the browser, whether in memory, sessionStorage or localStorage.

The SPA can now access or action protected resources from the service provider by including the header Authorization: Bearer <Access Token> in subsequent requests.

#### Specific Implicit Flow vulnerabilities

1) URL exposure

With the Access Token included in the URL, they will be visible in browser history.  

The full URL can also be unwittingly sent on to third party websites as part of the Referer header, if client site's Referrer Policy headers are not configured to prevent this.

2) Lack of refresh mechanism

Implicit Flow does not implement any refresh mechanism and doesn't provide refresh_tokens. 

To avoid frequent user re-authorization, the token must be long-lived and stored in browser localStorage. LocalStorage is relatively secure inaccessible from external processes. However as the data stored is persistent, there is a larger window of opportunity for malicious code - whether through an XSS attack or a device compromised by a malicious user, to access sensitive data such as the Access Token.

If tokens are short-lived, frequent user authorization requests are needed, and this could provide a greater opportunity for interception. 

Requiring users to frequently re-authenticate and re-authorize is also detrimental to user experience, especially when the authentication process involves MFA for example.

3) Redirect URL Interception

With the Access Token fully exposed in the post-authorization redirection URL, it provides a significant attack vector, far removed from the underlying Implicit Flow process, making potential exploits difficult to predict and defend against.

For example, on older Android and iOS operating systems, a vulnerability existed where multiple apps could be registered to handle the same custom URL scheme e.g. mycustomapp://. A malicious app could in some circumstances intercept a redirection using a scheme intended for a legitmate app, accessing any data in the URL.

#### Deprecation

Due to its inherent vulnerabilities, OAuth 2.0 Implicit Flow has been deprecated, although it is still supported by many service providers, including [Spotify](https://developer.spotify.com/documentation/web-api/tutorials/implicit-flow) and [Microsoft Identity Platform](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth2-implicit-grant-flow#prefer-the-auth-code-flow).

Instead Authorization Code Flow with PKCE is now the recommended standard for applications that cannot securely store a client secret.

Applications implementing Authorization Code Flow with PKCE avoid or mitigate the inherent vulnerabilities of Implicit Flow.


#### Additional authorization code step

Unlike implicit flow, Authorization Code Flow with PKCE includes the intermediate step of providing the client with an authorization code that is later used to exchange for Access Tokens. 

Access Tokens are obtained with an AJAX request to a token-exchange endpoint on the authentication server, which has the sole purpose of certifying a request's authorization code and returning an Access Token. This means the Access Token is not exposed to browser history, referer headers, or malicious browser extensions/scripts. 

Contrast this with implicit flow where the Access Token is returned in a full page redirection URL, visible to the user and stored in browser history.

The PKCE token exchange mechanism can also return refresh tokens giving the same [user-experience benefits](#### Obtaining-fresh-Access-Tokens-with-a-Refresh-Token
) as server-based Authorization Code Flow.

#### Securing the authorization code-Access Token exchange 

In the traditional Authorization Code Flow for server-backed client apps, when exchanging the authorization code for an Access Token, the client secret is included so that the authorization server knows the request originated from client server and can be trusted.

With SPAs, there is no way to either distribute or store an app-specific client secret securely on the browser.

Authorization Code Flow with PKCE uses a mechanism to certify that an Authorization Code-Access Token request belongs to the same user and client app instance that initiated the authorization process.

This is what the 'PKCE' (Proof Key for Code Exchange) part of the process is.

Authorization Code Flow with PKCE:

1)
The client app must first register with the service provider, with a client_id and a redirect_uri.

2)
When the user initializes the authorization process, first the client app uses a [CSPRNG](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator) to generate a unique string called the 'code_verifier'.

Then a 'code_challenge' is generated from the 'code_verifier', typically using a secure hash function like SHA-256.

The user's browser is then redirected to the authorization server, with the code_challenge and the method used to generate the code_challenge included in the URL:

```
https://authorization-server.com/authorize?response_type=code&client_id=CLIENT_ID&redirect_uri=REDIRECT_URI&scope=SCOPE&state=STATE&code_challenge=CODE_CHALLENGE&code_challenge_method=S256
```


As with traditional Authorization Code Flow, the redirect_uri is included to be checked with the one registered, as a security measure to prevent bogus requests redirecting the user to malicious sites or clones of the client app.

State is provided to [protect against CSRF attacks] (*** where state is described ***)

3)

The user then authenticates and grants the client app the requested scope permissions.

The authorization server then creates a temporary Authorization Code, and temporarily saves the code_challenge and the code_challenge_method with this Authorization Code. Later these will be used to verify the token exchange request belongs to the same client and user that inititated the process.

The authorization server then redirectes the browser back to the client app with the temporary Authorization Code:

```
https://my-pkce-client-app.com/callback?code=AUTHORIZATION_CODE&state=STATE
```

4) Token Exchange

The client app now makes an AJAX POST request to the authorization server's token exchange endpoint, with the Authorization Code and the code_verifier included in the URL-encoded form data:

```
    POST /token HTTP/1.1
    Host: authorization-server.com
    Content-Type: application/x-www-form-urlencoded

    grant_type=authorization_code&code=AUTHORIZATION_CODE&redirect_uri=REDIRECT_URI&client_id=CLIENT_ID&code_verifier=CODE_VERIFIER
```

Since the authorization server knows the code_challenge and code_challenge_method, it will apply the code_challenge_method to the code_verifier to confirm it matches the original code_challenge, and can trust the request.
 
It then returns a JSON response with the Access Token, along with a refresh_token if supported:

```json
    {
      "access_token": "ACCESS_TOKEN",
      "token_type": "bearer",
      "expires_in": EXPIRES_IN,
      "refresh_token": "REFRESH_TOKEN",
      "scope": "SCOPE"
    }
```

5) 

The post-authorization situation is now similar to that of traditional Authorization Code Flow.

The client app can now access their authorized resources with the Authorization: Bear <Access Token> header, with token refresh capabilities if provided.

## OpenID Connnect - OAuth 2.0 for Authentication

When OAuth 2.0 was developed, it was focused on providing a secure and standardized framework for allowing users to authorize third-party apps without sharing credentials.

OAuth 2.0 had no features specifically for authenticating users with third-party apps via identity providers, to say nothing for administering user roles, claims, and other attributes.

Originally, after OAuth 2.0 gained adoption, developers created their own custom solutions to include authentication. However, these solutions often differed significantly, sometimes leading to inconsistent or insecure implementations.

In response the OpenID Foundation developed a standardized protocol for Authentication with OAuth 2.0 called OpenID Connect (OIDC).

OIDC has been widely adopted and is supported by most identity providers and technology ecosystems including Google and Microsoft.

Since it is built on OAuth 2.0 protocols, knowledge of OAuth 2.0 flows makes it easy to understand OIDC too.

In fact, the changes needed to use OIDC with Authorization Code Flow or Authorization Code Flow with PKCE are so simple we can cover them together in just a few lines.

First, for your user's URL directing them to the authorization server, we just need to make sure 'openid' in included in the 'scope' parameter:

https://authorization-server.example.com/authorize?
  response_type=code&
  client_id=client123&
  scope=openid%20profile%20email&
  redirect_uri=https%3A%2F%2Fclient-app.example.com%2Fcallback&
  state=abc123

Second, when the Access Token is received from authorization code exchange, the JSON payload also includes an 'id_token', a JWT containing the authorized user's identity details.


### Authentication and Authorization in one flow

So we've seen how to implement user authentication with OIDC, and how it's a simple extension of OAuth 2.0 Authorization Code Flows.

And OAuth 2.0's function is enabling third-party apps to integrate with service providers and access protected resources, without holding user credentials.

As a result, it becomes possible for a user to authenticate with an identity provider, and authorize access to a resource server, in one flow. 

For example, we have built a third-party application that integrates with an e-commerce site. The e-commerce site has an API that allows authorized applications access to its 'resources', which we'll call functionality for this example. This is our resource server. 

Our app is very useful for users of the e-commerce site, as it adds lots of additional funtionality and automation capabilities that the site lacks.

The e-commerce site trusts Google as an identity provider and supports OAuth 2.0.

Lets say User 1, an avid user of the e-commerce site, has a Google account, and our app uses Google as the identity provider. 

With one user flow, User 1 can simultaneously login to our app by authenticating with Google, and also grant our client app permission to access certain features of the e-commerce site on their behalf. Since integrating with and improving those features is why User 1 likes our app!

To achieve this, we need to make sure that the scopes we include in the initial authorization request include 'openid' for authentication, and the additional scope values defined by the e-commerce site that represent the features we wish to gain access to. The scope values need to be configured with the identity provider and resource server.

Assuming the User 1 has granted authorization, the Authorization Code Flow will send the client app an Access Token specific for accessing features on behalf of User 1. Other users will have their own Access Tokens, possibly with different permissions, so these need to be stored and used appropriately for our app to function correctly for each user.




*****

2) Lack of secure or convenient storage options

With Implicit Flow, the Access Token must be sent in the URL. This means storing it as an HttpOnly cookie, inaccessible to javascript and hence XSS, is not an option.

Session and in-memory storage are options, but they are both still vulnerable to XSS, and inconvenient for the user as they require reauthentication with the authorization server whenever the browser is restarted.

Finally localStorage does persist the token across browser-sessions, but the Access Token is vulnerable access from malicious users of the same device, especially considering that Implicit Flow does not implement refresh tokens 


