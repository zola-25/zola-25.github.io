---
title: "OAuth 2.0 Authorization Code Flow"
permalink: /post/oauth2-auth-code-flow
layout: default
tags: OAuth-2.0 Authorization Authentication Authorization-Code-Flow Access-Token Third-Party-Access 
is_series: true
series_title: "Web Security"
series_number: 5
---


### Authorization Code Flow Implemention 

This is most similar to the OAuth 1.0 flow. It is appropriate for server-based Client Apps, that can securely store Access Tokens from an Authentication Server.

1) **App Registration**

    First, like in OAuth 1.0, the Client App developers register the app with the Service Provider.

    During registration the app is assigned a *client_id*, a unique identifer for the app, and a *client_secret*, used for authenticating the app when requesting Access Tokens and should be kept confidential.
    
    In addition, during registration a *redirect_uri* must be provided, usedd to ensure the Authorization Server will send the user back to the genuine Client App after user authorization.

    To full demonstrate the implementation, we'll define an example Client Application with the necessary registration variables set:

    *The Client App's domain* - `authcodeflow.demoapp.com`

    *client_id* - **AuthCodeFlow_DemoApp**
    
    *client_secret* - **AuthCodeFlow_DemoApp_SECRET**
    
    *redirect_uri* - `https://authcodeflow.demoapp.com/callback`
    
    *The Authorization Server's authorization endpoint*: `https://auth.service.com/authorize`

2) **User Authorization Request**

    When the user authorization flow is initiated, a URL is generated by the Client App's server directing the user's browser to the Authorization Server, with a number of parameters set allowing the Authorization Server to identify the Client App authorizing and the permissions being requested:

    **client_id** - **AuthCodeFlow_DemoApp**
    
    **response_type** - Has its value set to 'code', which indicates the app is initiating the Authorization Code Flow
    
    **scope** - The list of permissions the Client App is asking the user to authorize. For this example we'll just set 'profile', as all ourexample Client App requires is to read the user's profile.
    
    **redirect_uri** - `https://authcodeflow.demoapp.com/callback`, encoded when sent as a URL parameter 
    
    <a name="state"></a>
    **state** - A random string value generated by the Client App's server specifically for the authorization request and saved to the user's session. The string is used to protect against CSRF attacks. 
    
    <a name="csrf"></a>
    A [CSRF attack](2022-06-01-browser-security-fundamentals.md#cross-site-request-forgery-csrf), by definition, tricks the user into initiating a request from a location outside of the genuine client site, such as from within an email or another site. Since the *state* value is generated for each user authentication session, when the same value is returned by the Authorization Server it confirms the response is for the same request that was initiated by the user.
    
    While the *client_id* and *redirect_uri* also to some degree confirm to the Authorization Server that the request came from a valid source, they are at risk of being intercepted by an attacker and used to mimic an genuine authorization request. It is only when the Client App's server compares the *state* value from the authorization response to the one it generated for the user session that the response is verified as genuine and the authorization flow can continue.

    It is recommended that the *state* value is generated using a [CSRNG](https://en.wikipedia.org/wiki/Cryptographically_secure_pseudorandom_number_generator) of at least 32 characters to be ensure uniqueness and unpredictability.

    However for the implementation examples, we will use this dummy state string that's easier to track, especially across multiple examples: 'OurOAuth2StateString'
    
    Given these parameters, the URL our Client App directs the user to looks like: 

    ```
    https://auth.service.com/authorize?response_type=code&client_id=AuthCodeFlow_DemoApp&scope=profile&state=OurOAuth2StateString&redirect_uri=https%3A%2F%2Fauthcodeflow.demoapp.com%2Fcallback
    ```

3) **Temporary Authorization Code Granted** 

    After the user successfully authenticates with the Authorization Server and authorizes the Client App's requested permissions, the Authorization Server redirects the user's browser back to the Client App via the *redirect_uri*, appending the *scope* and *code* as query parameters to the URL. The *code* value is the Temporary Authorization Code the Client App will use to obtain an Access Token:

    ```
    https://authcodeflow.demoapp.com/callback?code=TempAuth0rizati0nC0de&state=OurOAuth2StateString
    ```

    The Client App's server then makes a POST request to a specific token exchange endpoint on the Authorization Server. 
    
    The POST request contains the parameters:
    
    **client_id** - As before
    
    **redirect_uri** - As before
    
    **code** - The Temporary Authorization Code sent in the callback: TempAuth0rizati0nC0de

    **grant-type** - "authorization_code" to tell the Authorization Server this is the Authorization code flow
    
    **client_secret** - AuthCodeFlow_DemoApp_SECRET
    ```
    POST /token HTTP/1.1
    Host: auth.service.com
    Content-Type: application/x-www-form-urlencoded

    grant_type=authorization_code&code=TempAuth0rizati0nC0de&client_id=AuthCodeFlow_DemoApp&client_secret=AuthCodeFlow_DemoApp_SECRET&redirect_uri=https%3A%2F%2Fauthcodeflow.demoapp.com%2Fcallback
    ```

    These parameters should be sent as URL-encoded form data in the request body, to protect sensitive data, especially the *client_secret* that must be kept confidential.

4) **Access Token Exchange** 

    When the Authorization Server receives the POST request at the token exchange endpoint, it validates that the *client_id*, *client_secret* and *redirect_uri* match a registered app, and the *code* - the Temporary Authorization Code - has not expired and was issued for the app corresponding to the *client_id* and *client_secret*.
    
    Assuming the validation is successful, the server sends a response back to the Client App's server containing a JSON object with:
    
    ```json
    { 
        "access_token": "Acc3ssT0ken",
        "token_type": "Bearer",
        "expires_in": 3600, 
        "refresh_token": "Refr3shT0ken"
    }
    ```
    
    **access_token** - The Access Token is the granted to the Client App and sent in subsequent requests for resources.

    **expires_in** - The number of seconds this Access Token is valid for, so here it's valid for 1 hour before it expires, at which point the Client App can no longer access the protected resources. 

    *refresh_token* - The Refresh Token can be used to obtain a new Access Token when the issued one expires - they are covered in detail in the [following section](#maintaining-client-app-authorization). They are optional depending on the OAuth implementation an application use case - they may not be present in the JSON.

    This JSON data is stored on the server and associated with the user.

5) **Accessing Protected Resources**
    
    The Client App's server can then make API requests to the Service Provider for permitted resources on behalf of the user, by including the Access Token in the header:
    
    ```
    Authorization: Bearer <Access Token>
    ```
    
    By making these requests from the server, the Access Token is not exposed to the user's browser and remains secure. 

#### Maintaining Client App Authorization

If the Client App requires resource access on an ongoing basis to perform its function, it would be a poor user experience to require the user to re-authenticate and re-authorize each time using the Authorization Code Flow.

Instead the Client App can stay authorized with the Service Provider over a longer period, either by:

1) Being issued very-long lifetime Access Tokens. Long lifetime Access Tokens pose a greater risk of being exposed since they are sent with every request. Also, since not all OAuth 2.0 implementations support Access Token revokation, securing user resources against Client Apps using long lifetime Access Tokens can be difficult.

2) Use Refresh Tokens to gain fresh Access Tokens - if Refresh Tokens are supported by the OAuth 2.0 implementation

#### Obtaining fresh Access Tokens with a Refresh Token

Access Tokens expire when the *expires_in* time, set in the JSON sent from the token exchange endpoint, is reached. It is often prudent to gain a fresh Access Token at a set time before this expiry is reached, to maintain app continuity for the user.

When a fresh Access Token is required, the Client App server makes a POST request to the same token exchange endpoint on the Authorization Server that was called to in step 3) to gain the first Access Token.

The POST request should include in the request body, as URL-encoded form data:

**grant_type** - "refresh_token"

**refresh_token** - The Refresh Token from a secure store

**client_id** - As before

**client_secret** - As before

**scope** - The requested scopes, or omitted if the new Access Token is to have the same access as the expiring one

```
POST https://auth.service.com/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=Refr3shT0ken&client_id=AuthCodeFlow_DemoApp&client_secret=AuthCodeFlow_DemoApp_SECRET
```

Assuming the request, along with the Refresh Token, is validated, the token exchange will typically respond with the JSON:

```json
{ 
    "access_token": "NewAcc3ssT0ken",
    "token_type": "Bearer",
    "expires_in": 3600,
    "scope": "profile",
    "refresh_token": "Updat3dRefr3shT0ken"
}
```

**scope** - a list of scopes the new token has access to, if new scopes were set in the refresh request
**refresh_token** - An updated Refresh Token used to obtain the next Access Token when the updated one expires

However the exact JSON contents may vary with the OAuth 2.0 implementation. Some implementations may issue a new Refresh Token each time, others may only ever require the original for refresh Access Token requests.

This data is then linked to the authorized user and the new Access Token used as before.
