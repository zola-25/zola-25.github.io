---
title: "OAuth 2.0 Overview"
permalink: /post/oauth2-overview
layout: default
tags: OAuth-2.0 Authorization Authentication Authorization-Code-Flow PKCE ROPC Device-Authorization-Flow Implicit-Flow  Access-Token Third-Party-Access 
is_series: true
series_title: "Web Security"
series_number: 5
---

OAuth 2.0 both improves and expands upon OAuth 1.0, with simpler authentication processes, and a modular approach that allows for additional use-cases besides server-based Client App authorization.

In fact, OAuth 2.0 offers several *flows*, are appropriate for different scenarios. We'll give a brief overview of each one before delving into the implementation details of some of the more notable ones - such as those that are widely adopted (Authorization Code Flow), those with notable security vulnerabilities or protections (Implicit Flow vs PKCE), and those with interesting use cases (Device Authorization Flow).

> **Note**
>
> [On Terminology](#notes-on-terminology)

### Overview of OAuth 2.0 Flows

1) **Authorization Code Flow**

    Most similar to the OAuth 1.0 flow, used for server-based Client Applications, but easier to implement than OAuth 1.0.

    [Implementing Authorization Code Flow](2023-04-02-oauth2-auth-code-flow.md)


2) **Implict Flow (also called Implict Grant Flow)**

    Designed for applications that cannot fully secure application-specific secrets required for ensuring request authenticity.

    This includes Single Page Applications with zero server-side functionality, and native applications including mobile and desktop applications operating without a secure server backend.

    Implict Flow issues Access Tokens directly after user authorization. Has significant security vulnerabilities and its use is [no longer recommended](https://www.ietf.org/archive/id/draft-ietf-oauth-security-topics-17.html#name-implicit-grant) by the IETF.
    
    [Implicit Flow Implementation](2023-04-04-oauth2-implicit-flow.md)

3) **Authorization Code Flow with PKCE (Proof Key for Code Exchange)**

    The recommended alternative to Implicit Flow for applications unable to secure a client secret.
    
    This flow is similar to the standard OAuth 2.0 [Authorization Code Flow](2023-04-02-oauth2-auth-code-flow.md). It has fewer vulnerabilities than Implicit Flow, with PKCE limiting the Access Token's visibility and risk of interception; and ensuring the Access Token can only be received by the instance of the Client App in use by the authenticated user.

    [Implementing Authorization Flow with PKCE](2023-04-06-oauth2-pkce-auth-code-flow.md)

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


### User Authentication through OAuth 2.0 with OIDC

[User Authentication with OIDC](2023-04-03-oauth2-authentication-with-oidc.md)

******

#### Notes on Terminology

*Service Providers* are *First-party* apps - those that provide the user resources and functionality we wish to integrate with.

*Client Applications* are the *Third-party* apps to be integrated - usually smaller and requiring user-specific resources the service provider has access to.

*Authorization Servers* allow the Client App to authenticate and allows the user to grant the application permissions to resources on the Service Provider.

*Identity Providers* allow the user to authenticate, verifying their identity to any other service that might require it. This could be both the Client App and the Service Provider.

In some cases the functions of the Identity Provider, Authorization Server and Service Provider are all provided by the same service or organisation - for example Facebook provides user authentication, as well as allowing users to grant authorization to third-party applications to access user data, while being the Service Provider at the same time.

However there are plenty of Service Providers that use separate Identity Providers - it's common for an application to allow authentication with multiple providers such as Google, Microsoft, Apple and others. Instances of applications using separate Identity Providers and Authorization Servers are rare. Although they serve different functions, for the purpose of Client App integration they are usually configured together. 

For convenience, examples in these articles will assume the Identity Provider and the Authorization Server are the same service, and use the term Authorization Server even when the service is only providing user authentication.
