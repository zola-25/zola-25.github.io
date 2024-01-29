---
title: "Common Browser Security Concepts"
permalink: /post/browser-security-fundamentals
layout: default
tags: Browser Web HTTP HTML CORS CSRF SOP XSS
is_series: true
series_title: "Web Security"
series_number: 1
---

#### Same Origin Policy (SOP)

The Same Origin Policy is a browser security feature that prevents scripts running in one window accessing the data from another window (whether tabs, windows or iFrames), unless both windows have the same origin - being the the URL scheme, host and port.

The SOP restricts malicious sites reading sensitive information displayed by a target site, as well as restricting read access to the target site's cookies which may be maintaining an authenticated user state with the server. It also restricts malicious sites making Ajax requests to another site's domain. 

Restrictions on legitimate cross-origin Ajax requests can be alleviated by the target site implementing Cross-origin resource sharing (CORS), described later.


#### Cross-site request forgery (CSRF)

SOP only restricts malicious sites reading data from a sensitive site. It does not prevent a malicious site embedding a request to a target site into an element within its display, and tricking the user into making that request. 

For example, a malicious site could display an image tag such as

``` html
  <img src="https://bankingsite.com/transfer?amount=1000&destination=12345678"/>
```

If the user already has a active session cookie with bankingsite.com, and bankingsite.com processes the GET requests like this as a write request, then the malicious action will occur. The malicious site can't read any data returned by this request, because of the SOP of the browser, but it doesn't stop the write action from occurring.

This is why it's important that GET requests are only used to retrieve data, and not to mutate data on the server.

However, CSRF attacks can still mutate data using form POST requests that execute automatically on page load.

For example, if a malicious site loads with the following form:

``` html
  <form id="transfer" method="POST" action="https://bankingsite.com/transfer">
      <input type="number" name="amount" value="1000">
      <input type="text" name="destination" value="12345678">
  <form>
  <script>
      document.getElementById('transfer').submit();
  </script>
```

Then this POST request will be sent, along with any active session cookie with bankingsite.com. 

To prevent these kind of malicious CSRF POST requests, target servers can be set to only accept forms that have a pre-transmitted CSRF security token embedded as a hidden form input on genuine forms.

For example, a genuine form on the legitimate bankingsite.com would be generated like:

``` html
  <form id="transfer" method="POST" action="https://bankingsite.com/transfer">
      <input type="hidden" name="csrfToken" value="50F38290ksegat3khku3a98235">
      <input type="number" name="amount" value="1000">
      <input type="text" name="destination" value="12345678">
      <button type='submit'>Transfer</button>
  <form>
```
The CSRF token is generated on the server based on the user session and the time of generation, making it difficult or impossible to guess by the malicious site. The token is recorded on the server as part of the user session, and whenever a POST is made, the form input token is compared against the session CSRF token, only allowing the action to be performed if the tokens match.

In ASP.NET Core, antiforgery middleware is usually added by default with hidden CSRF token inputs automatically injected into any forms created:

https://learn.microsoft.com/en-us/aspnet/core/security/anti-request-forgery?view=aspnetcore-7.0#antiforgery-in-aspnet-core

#### Cross-origin resource sharing (CORS)

CORS is a mechanism to allow sites to make Ajax requests and read responses that are sent to a different domain from the host page.

By default the SOP restricts sites making Ajax requests to other domains. The requested domain server can be set to allow requests from certain domains, or all external domains.

CORS-compliant browsers will make a request to the external domain with an Origin HTTP header set to the requesting site:

``` 
  Origin: https://origin-site.com
```

If CORS is permitted for origin-site.com, the external domain server will respond with the Access-Control-Allow-Origin header in its response:

``` 
  Access-Control-Allow-Origin: https://origin-site.com
```

Or, if requests from all domains are allowed, it will respond with:

``` 
  Access-Control-Allow-Origin: *
```

Or an error will be returned if the site does not allow CORS for origin-site.com.

##### Pre-flight requests

Since some servers were developed before the CORS protocol became widely adopted, they are configured to believe that any request made to them is legitimate, due to the SOP which prevents all cross-origin data requests.

Pre-flight requests are made by the browser to check the external domain server understands the CORS protocol and the requested method is permitted:

``` 
  OPTIONS /
  Host: external-site.com
  Origin: https://origin-site.com
  Access-Control-Request-Method: PUT
```

If the external site undersands CORS and the requested action, it can respond with the headers:

```
  Access-Control-Allow-Origin: https://origin-site.com
  Access-Control-Allow-Methods: PUT
```
If the external site does not undersand the CORS protocol, it will return an error, and the browser will not make the request.

This prevents malicious sites taking advantage of the CORS protocol to make requests to sites that assume, due to the SOP, that all requests made are valid.

#### Cross-site scripting (XSS)

XSS is the injection of malicious scripts into a genuine web page, that can be executed in every browser that views that page. 

Sites that allow users to input their custom HTML markup, or display any custom content that is not sanitized for any malicious tags (e.g. `<script>` tags), can be vulnerable. 

Other ways to mitigate include escaping all HTML special characters, when user text input is not supposed to be rendered as HTML.
