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
















JSON Web Tokens (JWTs)


https://www.youtube.com/watch?v=8haNjnq26K4

** Javascript modules
