---
title: "HTTP Basic Access Authentication"
permalink: /post/http-basic-access-authentication
layout: default
tags: authentication basic session HTTP HTTPS
is_series: true
series_title: "Web Security"
series_number: 1
---

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

app.UseHttpsRedirection();

app.Run();
bool HasAuthorizationHeader(HttpContext httpContext)
{
    return httpContext.Request.Headers.ContainsKey(HeaderNames.Authorization);
}
```

Note the additional charset="UTF-8" returned in the WWWAuthenticate response header is used to specify the acceptable encoding for the username and password.

### Security implications of Basic Access Authentication

Given that the user's credentials are transmitted unencrypted to the server, they should be transmitted through HTTPS instead of HTTP.

As long as the browser application remains open, these credentials are sent with every subsequent request to the protected resource, which is a potential security vulnerability as it only requires one interception to have access to the client's credentials.

The credentials are stored in the browser's process memory and usually inaccessible to both users and developers, hence why they are lost when the browser application is closed. 

However, some modern browsers may prompt the user to store the credentials in their built-in password storage, as they would when a user first enters credentials into a more typical form-based login page.

<a href="https://gist.github.com/zola-25/c1137903a6f7213422859e473faf1179" target="_blank">Gist</a>
