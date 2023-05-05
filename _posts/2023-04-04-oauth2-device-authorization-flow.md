---
title: "OAuth 2.0 Device Authorization Flow"
permalink: /post/oauth2-device-authorization-flow
layout: default
tags: OAuth-2.0 Authorization Authentication Device-Authorization-Flow Smart-TVs Streaming Netflix Access-Token Third-Party-Access 
is_series: true
series_title: "Web Security"
series_number: 5
---


1. A user has an existing account with a streaming service (e.g. Netflix), (the Service Provider).
2. They have a smart TV with the service's app installed.
3. They wish to authorize this app to use their account (essentially just authenticating with the app).
4. They could authenticate manually through the app, but the user interface on the TV is difficult to use, so instead they authenticate on a user-friendlier device such as their mobile device. Device Authorization Flow is the process that enables this.

A simplified version of the Device Authorization Flow process works as follows:

The streaming app is prompted by the user to authorize.

The streaming app sends a request to the Authorization Server to initiate the authorization process.

The Authorization Server:

1) Geneates a random *device_code* to identify streaming app device being authorized.

2) Geneates a random *user_code* identifying the authorization process being started.

3) Stores these together on the server temporarily, as they will be needed for later verification when the user completes authorization.

4) Sends the streaming app the URL the user must navigate to on their mobile device, including the user_code, and the *device_code*:

{
  "device_code": "DEVICE_CODE",
  "authorization_url": "https://authorization.streaming-service.com/user-auth-page?USER_CODE",
}


The device begins making polling requests to the Authorization Server in the background, asking if the *device_code* has been authorized yet. 


The authorization URL can be rendered on the TV as a QR code, that the user can open on their mobile device. The authorization URL will be specific to the streaming service, it will open the streaming service's login page in the browser or the streaming service mobile app itself.

When the user authenticates, or if they are already authenticated, they will simply be asked if they wish to authorize the device app to use their account.

When the user confirms, the Authorization Server looks up the *device_code* for the user in its memory, verifies it matches the *device_code* in the polling requests, and returns an Access Token to the streaming app. 

The Access Token then allows the streaming app access to the user's account.



