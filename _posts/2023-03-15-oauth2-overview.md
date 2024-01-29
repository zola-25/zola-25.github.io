---
title: "OAuth 2.0 Overview"
permalink: /post/oauth2-overview
layout: default
tags: OAuth-2.0 Authorization Authentication Authorization-Code-Flow PKCE ROPC Device-Authorization-Flow Implicit-Flow  Access-Token Third-Party-Access 
is_series: true
series_title: "Web Security"
series_number: 8
---

OAuth 2.0 both improves and expands upon OAuth 1.0, with simpler authentication processes, and a modular approach that allows for additional use-cases besides server-based Client App authorization.

In fact, OAuth 2.0 offers several *flows*, are appropriate for different scenarios. We'll give a brief overview of each one before delving into the implementation details of some of the more notable ones - such as those that are widely adopted (Authorization Code Flow), those with notable security vulnerabilities or protections (Implicit Flow vs PKCE), and those with interesting use cases (Device Authorization Flow).

> **Note**
> [On Terminology]({% link _posts/2023-03-15-oauth2-overview.md#notes-on-terminology %})

### Overview of OAuth 2.0 Flows

1) **Authorization Code Flow**

    Most similar to the OAuth 1.0 flow, used for server-based Client Applications, but easier to implement than OAuth 1.0.

    [Implementing Authorization Code Flow](2023-04-01-oauth2-auth-code-flow.md)


2) **Implicit Flow (also called Implicit Grant Flow)**

    Designed for applications that cannot fully secure application-specific secrets required for ensuring request authenticity.

    This includes Single Page Applications with zero server-side functionality, and native applications including mobile and desktop applications operating without a secure server backend.

    Implicit Flow issues Access Tokens directly after user authorization. Has significant security vulnerabilities and its use is [no longer recommended](https://www.ietf.org/archive/id/draft-ietf-oauth-security-topics-17.html#name-implicit-grant) by the IETF.
    
    [Implicit Flow Implementation](2023-04-02-oauth2-implicit-flow.md)

3) **Authorization Code Flow with PKCE (Proof Key for Code Exchange)**

    The recommended alternative to Implicit Flow for applications unable to secure a client secret.
    
    This flow is similar to the standard OAuth 2.0 [Authorization Code Flow](2023-04-01-oauth2-auth-code-flow.md). It has fewer vulnerabilities than Implicit Flow, with PKCE limiting the Access Token's visibility and risk of interception; and ensuring the Access Token can only be received by the instance of the Client App in use by the authenticated user.

    [Implementing Authorization Flow with PKCE](2023-04-03-oauth2-pkce-auth-code-flow.md)

4) **Resource Owner Password Credentials (ROPC)**

    With ROPC, a user enters their credentials directly into the Client App, which then forwards them in an API request to the Authorization Server for authentication. The Authorization Server then returns an Access Token for the Service Provider.

    It is generally not recommended for applications operating on the open internet, and goes against the main rationale of OAuth which is enabling Client Applications authorized access to Service Providers without sharing user credentials.

    However an example use case for ROPC could be when a Client Application is highly trusted, and interacts with the Authorization Server within a closed network, such as a secure company intranet. 

5) **Client Credentials Flow**

    This is generally used for server-to-server communication with no user resource access required. 

    The Client Application authenticates itself with the Authorization Server, and receives an Access Token for the Service Provider. 

    The Client Application should be server-based to store their credentials securely.

6) **Device Authorization Flow**

    Device Authorization Flow is designed for authorizing Client Apps that run on a different device than one the user will use to authenticate with.

    Typically this is implemented for authorizing Client Applications on devices such as TVs, where user credential input is physically difficult or slow.

    Temporary user and device codes are generated to link the user's service account authorization with the device of the Client App requesting access 


    [Implementing Device Authorization Flow](2023-04-04-oauth2-device-authorization-flow.md)

******
### User Authentication through OAuth 2.0 with OIDC

OAuth was designed for application authorization, rather than user authentication. OpenID Connect (OIDC) is a subsequent extension of OAuth 2.0 that standardizes user authentication in addition to application authorization.

[User Authentication with OIDC](2023-04-05-oauth2-authentication-with-oidc.md)

******

#### Notes on Terminology

*Service Providers* are *First-party* apps - those that provide the user resources and functionality we wish to integrate with.

*Client Applications* are the *Third-party* apps to be integrated - usually smaller and requiring user-specific resources the service provider has access to.

*Authorization Servers* are what the Client App communicates with when the user wishes to grant the Client App access to the user-specific resources from the Service Provider. Usually Authorization Servers also handle user authentication, either through *Identity Providers*, or with the Service Provider if they handle user authentication themselves (i.e. they store user credentials and provide a login page).

*Identity Providers* verify the user is authentic, e.g. with email/password credentials and usually additional factors like One-Time Passwords. They can verify the user's identity to any other service that might require it, using standards such as OpenID. This is separate process from OAuth's *Service Provider-Client App* authorization, but authentication usually happens at the same time - a user will authorize a Client App, but must authenticate first. 

In some cases the functions of the Identity Provider, Authorization Server and Service Provider are all provided by the same service or organization - for example Facebook provides user authentication, as well as allowing users to grant authorization to third-party applications to access user data, while being the Service Provider at the same time.

However there are plenty of Service Providers that use separate Identity Providers - it's common for a Service Provider's site to allow user authentication with multiple providers such as Google, Microsoft, Apple and others. There is an extension of OAuth 2.0 called *OpenID Connect* (OIDC) that allows simultaneous user authentication with an Identity Provider, and Client App authorization with a Service Provider, in one user flow.

Even though an Authorization Server may use an external Identity Provider for authentication, for convenience, some examples in these posts will just refer to the Authorization Server providing both OAuth authorization *and* user authentication. 
