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

3) Scalability adjustments - Details such as a user's assigned Access Token need to be stored at both the service provider's server and the app client's server - if either of these need to be scaled horizontally, typical accommodations need to be made to ensure all server nodes access consistent data.


### OAuth 2.0

OAuth 2.0 both improves and expands upon OAuth 1.0, with a simpler, more transparent authentication mechanism, and a modular approach that has applications besides the authorization of server-based third-party apps in OAuth 1.0.

In fact, OAuth 2.0 offers several 'flows' that are appropriate for different scenarios:

#### Authorization code flow

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

Obtaining fresh Access Tokens with a Refresh Token

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



2) Implicit flow

This flow is designed for browser-only applications (such as SPAs) without a server backend. The browser cannot be relied upon to store client secrets securely.

...

3) Resource Owner Password Credentials (ROPC)

This flow allows a client app to receive a user's credentials unencrypted, and use them directly to obtain an access token. While generally not suitable for third-party app authorization across the open internet, it can be used when the client application is trusted and operates within a closed network.

4) Client Credentials Flow

For non-user-based applications to authenticate themselves and access resources. These client applications have their own credentials that they use to gain access tokens for resource access.

5) Device Authorization Flow

You have used this flow if you've ever logged in to a streaming service on a smart TV by scanning a QR code with your mobile. The QR code opens the service website with a preset code, and after you authenticate, the client app (being the streaming app on the smart TV) receives an access token.

6) Refresh Token Flow

This flow is used to improve user experience in other flows. When a client app receives an access token, they may also receive a refresh token. The refresh token allows the client app the receive new access tokens without needing to reauthenticate. 









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
