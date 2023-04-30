---
title: "Maintaining Authentication State with Session Cookies"
permalink: /post/maintaining-authentication-state-with-session-cookies
layout: default
tags: authentication security HTTPS HSTS state session cookie sessionID set-cookie ASP.NET-Core HttpOnly SameSite Secure
is_series: true
series_title: "Web Security"
series_number: 2
---

This is a widely used, browser-based approach for allowing a user to maintain their authentication state, thus avoiding having them constantly re-authenticate when accessing protected resources.

It's straightforward, and we'll demonstrate a simple implementation in ASP.NET Core, without using any external libraries. 

However it has numerous security vulnerabilities if misconfigured, so for production-use it is nearly always implemented on the server using proven third-party libaries, such as those available for .NET and PHP.

### Session Cookie Authentication Steps:

1) A user submits their username and password through a traditional HTML form. Since these are plain, unencrypted values, the connection to the server should *always* be over HTTPS. The request should always be a POST request as the credentials will be stored in the HTTP body, instead of a GET request where the credentials will be appended to the request URL which is recorded in browser history, as well as potentally being forwarded to external sites in the Referer header.

2) The server receives this request and validates the credentials. It then generates a unique, unguessable session ID using an [Cryptographically secure pseudorandom number generator](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator)(CSPRNG).

	A CSPRNG is used as it creates IDs that are unique, unpredictable and independent, ensuring a session ID cannot be guessed by an attacker.

	This ID is then associated with the user in the server's memory or database.

3) The server then sends back the ID in the set-cookie header. Any further navigation around the site sends the cookie back so the server knows the user is already authenticated and can track their actions across the site.

### Security considerations

The session ID cookie should only contain the randomly generated session ID, and not any other user-specific information that could be obtained by attackers.

#### set-cookie security attributes

1. HttpOnly - this ensures no javascript can access the cookie, preventing any XSS attack accessing the session ID.

2. SameSite - this stops the session ID being sent in cross-site requests. It should be set to Strict, ensuring the session ID is only sent with requests from the cookie's origin site, or Lax, which allows it to be set if the user is navigating to the origin site from an external site.

3. Domain - Similar to SameSite, if the Domain attribute is set on the cookie, the web browser will only send the cookie to the specified Domain and any subdomains of that root domain. However this can be a vulnerability if an attacker gains access to any subdomain of the root domain. For this reason it is recommended to avoid setting the Domain attribute on the session cookie, as then the browser will then only send the cookie to the root domain.

4. Path - ensures the cookie is only sent on the site paths specified. This should be set appropriately if a user only has authorization to access certain site locations.

5. Secure - ensures the cookie is only ever sent over HTTPS. Even if all content delivered from the site domain, including images and files, are available over HTTPS only, Secure should still always be set as it is possible to deceive the user into making an un-secured HTTP request, exposing the session ID.
	
	If supported, [HSTS](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html) can be used to force the browser to ensure all subsequent requests to the site domain are made over HTTPS.

6. Max-Age, Expires - The session ID cookie should not be set with Max-Age or Expires attributes. These persist the cookie beyond the browser session, storing the cookie on the device and potentially enabling malicious software access to the session ID.

### Library-free implementation in ASP.NET Core

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

### Ensuring session ID invalidation

Session IDs should expire and be removed from server storage after a set period of time. This helps prevent scenarios where an authenticated user leaves their device with the browser still open, allowing another - potentally malicous - user to use the device to access sensitive content.

Additionally, sites should provide authenticated users with a logout mechanism that acts to remove or invalidates the session ID on the server.
