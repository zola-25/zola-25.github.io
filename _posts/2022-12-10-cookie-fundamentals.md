---
title: "Cookies - A guide for developers"
permalink: /post/cookies-guide
layout: default
tags: cookies cookie browsers web authentication HTTP privacy
is_series: true
series_title: "Web Security"
series_number: 2
---

The HTTP protocol is by definition stateless. Before cookies, websites had no way of remembering your current state and preferences - for example, if you were already logged in to the site, or whether you had made site-specific actions or state, such as the current items in an e-commerce site's shopping cart. 

The name cookies originated from Unix, which were unique, opaque identifiers passed between programs. These [magic cookies](https://en.wikipedia.org/wiki/Magic_cookie) could represent an identity, an authorization or other agreement that the relevant program could interpret and act upon accordingly.

Cookies were first added as standard web functionality by Netscape in 1994. Netscape allowed web servers to send user-specific cookies that stored information specific to the client. These cookies received by the client were stored in the user's browser for each site, and could only be set and read by the originating site - meaning, for security, a malicious site could not read another site's browser-stored cookies.

When a user makes further requests to a site that has sent cookies, these cookies are sent back to the site in HTTP headers, allowing the web server to identify the user and their current state.

## Example ASP.NET Core Implementation

When a cookie is sent from the server to the client, it is sent in the HTTP response as a `set-cookie` header. Using a simple ASP.NET Core Program.cs to serve a static HTML page, we can define a simple cookie using middleware that will be sent to the client on each request:

```csharp

var builder = WebApplication.CreateBuilder(args);

var app = builder.Build();

app.Use(async (context, next) =>
{
    context.Response.Cookies.Append("cookieId", "cookieData");

    // Call the next delegate/middleware in the pipeline.
    await next(context);
});

app.UseHttpsRedirection();

app.UseDefaultFiles(); 
app.UseStaticFiles();

app.Run();
```

The cookie is then set in the HTTP response header from the server response:

<img width="296" alt="image" src="https://user-images.githubusercontent.com/29863888/232394919-ae6cf3f6-d5ba-419a-aad3-42865c980595.png">

And then stored in the browser:

<img width="810" alt="image" src="https://user-images.githubusercontent.com/29863888/232393715-33416536-796c-46df-b3f8-0556802c9efd.png">

For any subsequent requests made by the client to the server, the cookie is included in the request header:

<img width="428" alt="image" src="https://user-images.githubusercontent.com/29863888/232350881-8af64c6b-fd24-4aad-89cc-1b015d899e68.png">


## Cookie attributes

### Session vs Permanent cookies

Permanent cookies either contain the attribute `Expires`, which sets a date where the cookie is to be deleted by the browser, or a `Max-Age` attribute, which defines a set length of time the cookie lasts before being deleted. The value for `Max-Age` should be the number of seconds the cookie lasts before expiry.

Session cookies, on the other hand, are deleted when the browser session ends.

### Cookie security attributes

#### The Secure attribute

The `Secure` attribute will stop the cookie being set from a site without the HTTPS protocol (i.e. http://). However a malicious agent with access to the client hard-drive can still read and modify the cookie data. 

Also, a malicious script from web page with the same domain as the cookie can read and modify the cookie data.

#### The HttpOnly attribute

A cookie with the `HttpOnly` attribute is inaccessible to any javascript, even script originating from the same site as the cookie was sent from. 

For example, Cookies that are used to maintain authentication state do not need to be accessed from Javascript, and only need to be sent in HTTP requests back to the server to demonstrate existing authentication state.

#### The Domain and Path attributes

When the `Domain` attribute is not set by the response, the cookie is only sent back to the exact domain where the cookie originated from.

When a `Domain` attribute is specified, the cookie is sent back to the originating parent domain as well as all subdomains of the parent.

If a `Path` attribute is set, the cookie will only be sent back to the requesting page that contains that path, for example if the `Domain` attribute is set to example.com, and the `Path` is set to /SubPath, the cookie will only be sent back if the page requested is example.com/SubPath, or any subdomain of example.com e.g. subdomain.example.com/SubPath.

#### The SameSite attribute

The `SameSite` attribute determines whether a cookie can be sent with a cross-site request. 

This is important for protecting against CSRF attacks.

If a malicious POST is engineered to be sent from a genuine site to an external site, the cookie from the origin page will be sent with the request. 

This is mitigated to vary degrees by setting the `SameSite` attribute on the cookie with these values:

1. `Strict`: The cookie can only be sent to the origin domain

2. `Lax`: The cookie can only be sent to its origin site when navigating to the cookie's origin site from an external site. This is the default behavior, if the `SameSite` attribute is not set.

3. `None`: The cookie is sent to any external site request from the origin page. This option requires the `Secure` attribute to be set, enforcing that cookie can only be transmitted to the external site through HTTPS. As mentioned above, the `Secure` attribute does not prevent a malicious script reading or modifying the cookie unless the `HttpOnly` attribute is also set.

Adding these attributes through ASP.NET Core middleware:

``` csharp
app.Use(async (context, next) =>
{
    context.Response.Cookies.Append("cookieId", "cookieData", new CookieOptions()
    {
        Secure = true,
        HttpOnly = true,
        SameSite = SameSiteMode.Strict,
    });

    // Call the next delegate/middleware in the pipeline.
    await next(context);
});
```

The cookie is then sent from the server with the set attributes:

<img width="472" alt="image" src="https://user-images.githubusercontent.com/29863888/232394530-fe4bad00-94d3-404c-95d3-53d78673bf24.png">

And stored by the browser with the set attributes:

<img width="804" alt="image" src="https://user-images.githubusercontent.com/29863888/232393987-6b0d1c91-5b45-47e1-b15a-533b1efd5856.png">

**Note**

Due to the standards adopted for cookie headers, the `Domain` attribute must have at least two dots for security purposes, to prevent top-level domains of the form .com being set. Since this test example used localhost, which has no dots, the `Domain` attribute has been omitted. When the `Domain` attribute is omitted, it defaults to the hostname of the server, which is localhost. This issue has been [widely catalogued](https://stackoverflow.com/a/1188145/3910619).


## Third-party cookies

When a page is requested from a server, the page may include elements that are loaded from an external domain, which may set its own cookies originating from that domain. These are known as Third-party cookies. 

When the user then browses to other sites, these cookies are then sent on to these sites. These sites can then use these cookies to track the browsing habits of the user.

The browser HTTP request made to the external (Third-party) site contains details of your device, such as IP address, browser type, device information and the URL of the site you visited. 

This data is then stored in a cookie and sent back to your browser for storage. These details can be used to create a cookie with a unique identifier that is subsequently sent to other sites you visit.

Other sites accessing these cookies can then update the information stored in the cookie with information based on your further browsing activity, such as recording the new website you visit, pages viewed and any other behavioral data relating to that site.

Further browsing allows sites to build a profile of your browsing habits. This personal data can then be sold to data brokers, advertisers, marketing companies, political organizations and other entities that can benefit from personalized data. Data breaches can even result in this information being sold illicitly, such as through the dark web.

## Helpful Links

1. [Great YouTube video on Cookie Fundamentals](https://www.youtube.com/watch?v=lF1kat22hB8)
2. [Cookie RFC specification](https://curl.se/rfc/cookie_spec.html)

