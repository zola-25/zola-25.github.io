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

[Notes on Terminology](#notes-on-terminology)

In fact, OAuth 2.0 offers several *flows*, are appropriate for different scenarios. We'll give a brief overview of each one before delving into the implementation details of some of the more notable ones - such as those that are widely adopted (Authorization Code Flow), those with notable security vulnerabilities or protections (Implicit Flow vs PKCE), and those with interesting use cases (Device Authorization Flow).

### Overview of OAuth 2.0 Flows

1) **Authorization Code Flow**

    Most similar to the OAuth 1.0 flow, used for server-based Client Applications, but easier to implement than OAuth 1.0.

    [Implementing Authorization Code Flow](oauth2-auth-code-flow.md)


2) **Implict Flow (also called Implict Grant Flow)**

    Designed for applications that cannot fully secure application-specific secrets required for ensuring request authenticity.

    This includes Single Page Applications with zero server-side functionality, and native applications including mobile and desktop applications operating without a secure server backend.

    Implict Flow issues Access Tokens directly after user authorization. Has significant security vulnerabilities and its use is [no longer recommended](https://www.ietf.org/archive/id/draft-ietf-oauth-security-topics-17.html#name-implicit-grant) by the IETF.
    
    [Implicit Flow Implementation](oauth2-implicit-flow.md)

3) **Authorization Code Flow with PKCE (Proof Key for Code Exchange)**

    The recommended alternative to Implicit Flow for applications unable to secure a client secret.

    [Implementing Authorization Flow with PKCE](oauth2-pkce-code-flow.md)

4) **Resource Owner Password Credentials (ROPC)**

    With ROPC, a user enters their credentials directly into the Client App, which then forwards them in an API request to the Authorization Server for authentication. The Authorization Server then returns an Access Token for the Service Provider.

    It is generally not recommended for applications operating on the open internet, and goes against the main rationale of OAuth which is enabling Client Applications authorized access to Service Providers without sharing user credentials.

    However an example use case for ROPC could be when a Client Application is highly trusted, and interacts with the Authorization Server within a closed network, such as a secure company intranet. 

4) **Client Credentials Flow**

    This is generally used for server-to-server communication with no user resource access required. 

    The Client Application authenticates itself with the Authorization Server, and receives an Access Token for the Service Provider. 

    The Client Application should be server-based to store their credentials securely.

5) **Device Authorization Flow**

    Device Authorization Flow is designed for authorizing Client Apps that run on a different device than one the user will use to authenticate with.

    Typically this is implemented for authorizing Client Applications on devices such as TVs, where user credential input is physically difficult or slow.

    Temporary user and device codes are generated to link the user's service account authorization with the device of the Client App requesting access 


    [Implementing Device Authorization Flow](oauth2-device-authorization-flow.md)


### Authentication through OAuth 2.0 with OIDC

[Adding Authentication with OIDC](oauth2-authentication-with-oidc.md)


