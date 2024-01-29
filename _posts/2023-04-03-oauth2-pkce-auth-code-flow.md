---
title: "OAuth 2.0 Authorization Code Flow with PKCE"
permalink: /post/oauth2-pkce-auth-code-flow
layout: default
tags: OAuth-2.0 Authorization Authentication Authorization-Code-Flow PKCE Implicit-Flow Access-Token Third-Party-Access 
is_series: true
series_title: "Web Security"
series_number: 11
---

> **Note**
> [On Terminology](/post/oauth2-overview#notes-on-terminology)

Unlike implicit flow, Authorization Code Flow with PKCE includes the intermediate step of providing the client with an Authorization Code that is later used to exchange for Access Tokens. 

Access Tokens are obtained with an AJAX request to a token-exchange endpoint on the Authorization Server, which has the sole purpose of certifying a request's Authorization Code and returning an Access Token. This means the Access Token is not exposed in browser history, or malicious browser extensions/scripts. 

Contrast this with Implicit Flow where the Access Token is returned in a full page redirection URL, visible to the user and stored in browser history.

The PKCE token exchange mechanism can also return refresh tokens giving the same [user-experience benefits](/post/oauth2-auth-code-flow#maintaining-client-app-authorization) as server-based Authorization Code Flow.

#### Securing the Authorization Code-Access Token exchange 

In the traditional Authorization Code Flow for server-backed Client Apps, when exchanging the Authorization Code for an Access Token, the client secret is included so that the Authorization Server knows the request originated from Client App's server and can be trusted.

With SPAs, there is no way to either distribute or store the client secret securely, considering the multiple browser instances running the application.

Authorization Code Flow with PKCE uses a mechanism to certify that an Authorization Code-Access Token request belongs to the same user and Client App instance that initiated the authorization process.

Authorization Code Flow with PKCE:

1) **App Registration**

As with other Client App OAuth 2.0 authorization flows, the Client App must first register with the Service Provider, with a *client_id* and a *redirect_uri*.

*The Client App's domain* - `pkce.authcodeflow.demoapp.com`

*client_id* - **PkceAuthCodeFlow_DemoApp**

*redirect_uri* - `https://pkce.authcodeflow.demoapp.com/callback`

*The Authorization Server's authorization endpoint* - `https://auth.service.com/authorize`

2) **User Authorization Request**

When the user initializes the authorization process, first the Client App uses a [CSPRNG](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator) to generate a unique string called the *code_verifier*. 

The *code_verifier* should be between 43 and 128 characters long, and for the sake of simplicity and easier debugging, should consist of only URL-safe characters that require no encoding (a-z, A-Z, 0-9, hyphens and underscores will work fine).

Then a *code_challenge* is generated from the *code_verifier*, typically using a secure hash function like SHA-256.

Let's not use dummy values this time and do this for real with a pseudo-random number for our *code_verifier*:

*code_verifier*: iQhYcRvP8zSxL6mA0tN_fE2DGZ1XjKUokbOeHsn7wYM4-lWpV

We SHA-256 hash the *code_verifier* to get the *code_challenge*: c46b62c38870e17ae9a33b0c901e6665241b54a594dcc981e2ac214897d061c1

The user's browser is then redirected to the Authorization Server, with the *code_challenge* and the method used to generate the *code_challenge* included in the URL:

```
https://auth.service.com/authorize?response_type=code&client_id=PkceAuthCodeFlow_DemoApp&scope=profile&state=OurOAuth2StateString&code_challenge=c46b62c38870e17ae9a33b0c901e6665241b54a594dcc981e2ac214897d061c1&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fpkce.authcodeflow.demoapp.com%2Fcallback
```

As with traditional Authorization Code Flow, the *redirect_uri* is included to be checked with the one registered, as a security measure to prevent bogus requests redirecting the user to malicious sites or clones of the Client App, along with a [state value](/post/oauth2-auth-code-flow#state), that we check for CSRF safety.

3) **Temporary Authorization Code Granted** 

The user then authenticates and grants the Client App the requested *scope* permissions.

The Authorization Server then creates a temporary Authorization Code, and temporarily saves the *code_challenge* and the *code_challenge_method* with this Authorization Code. Later these will be used to verify that the token exchange request belongs to the same Client App, and for the same user, that initiated the process.

The Authorization Server then redirects the browser back to the Client App with the temporary Authorization Code:

```
https://pkce.authcodeflow.demoapp.com/callback?code=TempAuth0rizati0nC0de&state=OurOAuth2StateString
```

4) **Access Token Exchange**

The Client App now makes an AJAX POST request to the Authorization Server's token exchange endpoint, with the Authorization Code and the *code_verifier* included in the URL-encoded form data:

```http
POST /token HTTP/1.1
Host: auth.service.com
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=TempAuth0rizati0nC0de&redirect_uri=https%3A%2F%2Fpkce.authcodeflow.demoapp.com%2Fcallback&client_id=PkceAuthCodeFlow_DemoApp&code_verifier=iQhYcRvP8zSxL6mA0tN_fE2DGZ1XjKUokbOeHsn7wYM4-lWpV
```

Since the Authorization Server knows the *code_challenge* and *code_challenge_method*, it will apply the *code_challenge_method* to the *code_verifier* to confirm it matches the original *code_challenge*, and can trust the request.
    
It then returns a JSON response with the Access Token, along with a refresh_token if supported:

```json
{
    "access_token": "Acc3ssT0ken",
    "token_type": "Bearer",
    "expires_in": 3600,
    "refresh_token": "Refr3shT0ken",
}
```

5) **Accessing Protected Resources**

The Client App can now make requests for protected resources in the usual manner, except requests are made from the browser if there is no server backend, as may be the case with a SPA. The Access Token is added in the Authorization Header:


```
Authorization: Bearer Acc3ssT0ken
```

If supported by the OAuth 2.0 implementation, the same [Refresh Token mechanism](/post/oauth2-auth-code-flow#obtaining-fresh-access-tokens-with-a-refresh-token) outlined for regular Authorization Code Flow can be used to gain new Access Tokens when they near expiry. 
    

