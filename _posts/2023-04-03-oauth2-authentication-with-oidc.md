    
## OpenID Connnect - OAuth 2.0 with Authentication

When OAuth 2.0 was developed, it was focused on providing a secure and standardized framework for allowing users to authorize Client Apps without sharing credentials.

OAuth 2.0 had no features specifically for authenticating users with Client Apps via identity providers, to say nothing for administering user roles, claims, and other attributes.

Originally, after OAuth 2.0 gained adoption, developers created their own custom solutions to include authentication. However, these solutions often differed significantly, sometimes leading to inconsistent or insecure implementations.

In response the OpenID Foundation developed a standardized protocol for Authentication with OAuth 2.0 called OpenID Connect (OIDC).

OIDC has been widely adopted and is supported by most identity providers and technology ecosystems including Google and Microsoft.

Since it is built on OAuth 2.0 protocols, knowledge of OAuth 2.0 flows makes it easy to understand OIDC too.

In fact, the changes needed to use OIDC with Authorization Code Flow or Authorization Code Flow with PKCE are so simple we can cover them together in just a few lines.

First, for your user's URL directing them to the Authorization Server, we just need to make sure openid in included in the *scope* parameter:

```
https://auth.service.com/authorize?response_type=code&client_id=AuthCodeFlow_DemoApp&scope=openid&redirect_uri=https%3A%2F%2Fauthcodeflow.demoapp.com%2Fcallback&state=OurOAuth2StateString
```

Second, when the Access Token is received from Authorization Code exchange, the JSON payload also includes an *id_token*, a JWT containing the authorized user's identity details.


### Authentication and Authorization in one flow

So we've seen how to implement user authentication with OIDC, and how it's a simple extension of OAuth 2.0 Authorization Code Flows.

And OAuth 2.0's function is enabling Client Apps to integrate with Service Providers and access protected resources, without holding user credentials.

As a result, it becomes possible for a user to authenticate with an identity provider, and authorize access to a resource server, in one flow. 

For example, we have built a Client Application that integrates with an e-commerce site. The e-commerce site has an API that allows authorized applications access to its *resources*, which we'll call functionality for this example. This is our resource server. 

Our app is very useful for users of the e-commerce site, as it adds lots of additional funtionality and automation capabilities that the site lacks.

The e-commerce site trusts Google as an identity provider and supports OAuth 2.0.

Lets say User 1, an avid user of the e-commerce site, has a Google account, and our app uses Google as the Identity Provider. 

With one user flow, User 1 can simultaneously login to our app by authenticating with Google, and also grant our Client App permission to access certain features of the e-commerce site on their behalf. Since integrating with and improving those features is why User 1 likes our app!

To achieve this, we need to make sure that the scopes we include in the initial authorization request include openid for authentication, and the additional scope values defined by the e-commerce site that represent the features we wish to gain access to. The scope values need to be configured with the identity provider and resource server.

Assuming the User 1 has granted authorization, the Authorization Code Flow will send the Client App an Access Token specific for accessing features on behalf of User 1. Other users will have their own Access Tokens, possibly with different permissions, so these need to be stored and used appropriately for our app to function correctly for each user.


