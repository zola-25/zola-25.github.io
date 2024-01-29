---
title: "OAuth 2.0 Device Authorization Flow"
permalink: /post/oauth2-device-authorization-flow
layout: default
tags: OAuth-2.0 Authorization Authentication Device-Authorization-Flow Smart-TVs Streaming Netflix Access-Token Third-Party-Access 
is_series: true
series_title: "Web Security"
series_number: 12
---

> **Note**
> [On Terminology](2023-03-15-oauth2-overview.md#notes-on-terminology)


Device Authorization Flow is designed for authorizing Client Apps that run on a different device than one the user will use to authenticate with - typically this is used for authorizing streaming apps on Smart TVs to access a user's existing account, and grant them access to use it to stream data through the streaming app on the TV (the Client App).

#### A typical situation involves:

- A user has an existing account with a streaming service (e.g. Netflix), (the Service Provider).

- They have a smart TV with the service's app installed (the Client App).

- They wish to authorize this Client App to use their account (essentially just authenticating with the app from the user's perspective, but described accurately as authorization).

- They could authenticate manually through the app, but the user interface on the TV is difficult to use, so instead they authenticate on a user-friendlier device such as their mobile device. 
  
  It's also often the case that they are already authenticated with the service's mobile app equivalent, or a different mobile app that is using the same Identity Provider as the service, in which case they just need to tap Yes a confirmation popup (for example, authorization requests are often sent through the YouTube App for related Google services). It is the Device Authorization Flow process that enables this functionality.


#### Implementation

A simplified version of the Device Authorization Flow process works as follows:

1) **User Initiates Authorization Flow**

    The streaming app is prompted by the user to authorize, and so the streaming app sends a request to the Authorization Server to initiate the authorization process.

    The Authorization Server:

    1) Generates a random *device_code* to identify streaming app device being authorized.

    2) Generates a random *user_code* identifying the authorization process being started.

    3) Stores these together on the server temporarily, as they will be needed for later verification when the user completes authorization.

    4) Sends the streaming app the URL the user must navigate to on their mobile device, including the *user_code*, and the *device_code*, in a JSON response:

    ```json
    {
        "device_code": "DEVICE_CODE",
        "authorization_url": "https://authorization.streaming-service.com/user-auth-page?USER_CODE",
    }
    ```

2) **Device Begins Background Polling**
    
    
    The device begins making polling requests to the Authorization Server in the background, asking if the *device_code* has been authorized yet. 
    

3) **User Authorizes on Mobile Device**

    The authorization URL can be rendered on the TV as a QR code, that the user can open on their mobile device. The authorization URL will be specific to the streaming service, it will open the streaming service's login page in the browser or the streaming service mobile app itself.

    When the user authenticates, or if they are already authenticated, they will simply be asked if they wish to authorize the device streaming app to use their account.

    When the user confirms, the Authorization Server looks up the *device_code* for the user in its memory, verifies it matches the *device_code* in the polling requests, and returns an Access Token to the streaming app. 

4) **Client App Accesses User's Resources**

    The Access Token now allows the streaming app access to the user's account, and is typically sent in the Authorization header on the necessary requests:

    ```
    Authorization: Bearer <Access Token>
    ```



