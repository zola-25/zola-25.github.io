---
title: "Cookies - The Essentials"
permalink: /post/cookie-essentials
layout: default
tags: cookies cookie browsers web authentication HTTP
---



## Maintaining State

https://www.youtube.com/watch?v=lF1kat22hB8

The HTTP protocol is by definition stateless. Before cookies, websites had no way of remembering your current state and preferences - for example, if you were already logged in to the site, or whether you had made site-specific actions or state, such as the current items in an e-commerce site's shopping cart. 

The name cookies originated from Unix, which were unique, opaque identifiers passed between programs. These 'magic cookies' could represent an identity, an authorization or other agreement that the relevant program could interpret and act upon accordingly.

https://en.wikipedia.org/wiki/Magic_cookie

Cookies were first added as standard web functionality by Netscape in 1994. Netscape allowed web servers to send user-specific cookies that stored information specific to the client. These cookies received by the client were stored in the user's browser for each site, and could only be set and read by the originating site - meaning, for security, a malicious site could not read another site's browser-stored cookies.

When a user makes further requests to a site that has sent cookies, these cookies are sent back to the site in HTTP headers, allowing the web server to identify the user and their current state.

## Implementation

When a cookie is sent from the server to the client, it is sent in the HTTP reponse as a set-cookie header:

'''
set-cookie: cookieId=cookieData
'''

This is then stored in the browser specific to the site:



