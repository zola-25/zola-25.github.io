---
title: "Web Authentication"
permalink: /post/web-authentication
layout: default
tags: authentication basic jwt session HTTP HTTPS privacy
---

### HTTP Basic Access Authentication

Basic Access Authentication is probably the simplest authentication method to implement.

When an unauthenticated user tries to access a restricted resource, the server responds with a 401 and a WWW-Authenticate response header field, with the header value 'Basic realm="[Name given to resource user is trying to access]"'.

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
        if (!httpContext.Request.Headers[HeaderNames.Authorization].Any())
        {
            httpContext.Response.Headers.Add(HeaderNames.WWWAuthenticate,
                new StringValues(new[] { "Basic", "realm=\"User Visible Realm\", charset=\"UTF-8\"" }));
            return Results.Unauthorized();
        }
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

bool HasAuthorizationHeader(HttpContext httpContext)
{
    return httpContext.Request.Headers.ContainsKey(HeaderNames.Authorization);
}
```

Note the additional charset="UTF-8" returned in the WWWAuthenticate response header is used to specify the acceptable encoding for the username and password.

#### Security implications of Basic Access Authentication

Given that the user's credentials are transmitted unencrypted to the server, they should be transmitted through HTTPS instead of HTTP.

As long as the browser application remains open, these credentials are sent with every subsequent request to the protected resource, which is a potential security vulnerability as it only requires one interception to have access to the client's credentials.

The credentials are stored in the browser's process memory and usually inaccessible to both users and developers, hence why they are lost when the browser application is closed. 

However, some modern browsers may prompt the user to store the credentials in their built-in password storage, as they would when a user first enters credentials into a more typical form-based login page.


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

Instead of using JWTs to hold sensitive information, [JWE tokens](https://datatracker.ietf.org/doc/html/rfc7516){:target="_blank"} can be used to secure payload data. However they have a more complex implementation than JWTs, requiring more resources to generate and verify, and are much larger than standard JWTs.

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

3) Scalability adjustments - Details such as a user's assigned Access Token need to be stored at both the service provider's server and the app client's server - if either of these need to be scaled horizontally, typical accommodations need to be made to ensure all server nodes access to consistent data.



#### OAuth 2.0 flow




would redirect them to the first-party site's authentication process,



When a user authenticates with the Identiy Provider, 

to of allowing users of websites widely used, established digital ecosytems (such as Microsoft and Google) and 'Identity Provider' of Third-Party applications 


### Standard authentication flows using JWT tokens




The OAuth 2.0 framework recommends JWT tokens are sent from the client in the authorization header:

`Authorization: Bearer [full JWT token]`

This 

There are work-arounds for this, which form part of 


JSON Web Tokens (JWTs)


https://www.youtube.com/watch?v=8haNjnq26K4

** Javascript modules
