---
title: "OpenID Connect - OAuth 2.0 with Authentication"
permalink: /post/oauth2-authentication-with-openID-connect
layout: default
tags: OAuth-2.0 OpenID-Connect OIDC Authentication Access-Token
is_series: true
series_title: "Web Security"
series_number: 12
---

> **Note**
> [On Terminology](/post/oauth2-overview#notes-on-terminology)

When OAuth 2.0 was developed, it was focused on providing a secure and standardized framework for allowing users to authorize Client Apps without sharing credentials.

OAuth 2.0 had no features specifically for authenticating users with Client Apps via Identity Providers, to say nothing for administering user roles, claims, and other attributes.

Originally, after OAuth 2.0 gained adoption, developers created their own custom solutions to include authentication. However, these solutions often differed significantly, sometimes leading to inconsistent or insecure implementations.

In response the OpenID Foundation developed a standardized protocol for Authentication with OAuth 2.0 called OpenID Connect (OIDC).

OIDC has been widely adopted and is supported by most identity providers and technology ecosystems including Google and Microsoft.

Since it is built on OAuth 2.0 protocols, knowledge of OAuth 2.0 flows makes it easy to understand OIDC too.

The main feature OIDC add to OAuth 2.0, whether using Authorization Code Flow or Authorization Code Flow with PKCE, is including a signed JWT ***ID Token*** in addition to the Access Token at the Temporary Authorization Code exchange step.

The Client App validates the authenticity of the ID Token based on its signature and other properties known to the Client App, such as the issuer URL. Additional security and verification methods can be used depending on the implementation: [ID Token Validation Standards](https://openid.net/specs/openid-connect-core-1_0.html#rfc.section.3.1.3.7)

If requested by the Client App, and authorized by the user, the ID Token can also include user details such as their email address or name. It may be the case that these are all that the Client App requires, with no Service Provider API requests needed, making the Access Token redundant. 


