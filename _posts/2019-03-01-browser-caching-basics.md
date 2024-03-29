---
title: "Browser Caching Basics"
permalink: /post/browser-caching-basics
layout: default
tags: browser caching cache chrome firefox edge
---

Browsers cache web content to deliver previously visited pages faster.

This caching can be controlled by the web server with the HTTP header cache-control (sometimes also using the header e-tag), as explained later.

If the cache-control header is not set, the browser will use [heuristics](https://stackoverflow.com/questions/14345898/what-heuristics-do-browsers-use-to-cache-resources-not-explicitly-set-to-be-cach/31852117#31852117) to determine the length of time to cache the resource, usually 10% of the timespan between download date and last-modified-by header if set. For instance if a file was downloaded on the 10th of January, was last modified on the server on the 1st of January, the browser will cache the file for a day.

If even the last-modified-header is not set, the resource may or may not be cached depending on the browser. Browsers [generally won't cache](https://stackoverflow.com/questions/5477566/no-last-modified-http-header-however-cached) if there is nothing they can use to base a timeout on. It seems they may store the file in the cache (perhaps needed when browsing offline), but subsequent requests will go back to the server.

You can verify this with a simple action method in any ASP.NET Core site. Set the method to return some content and add a HTML link tag to the resource:

```csharp
[Route("cacheTest.css")]
public IActionResult CacheTest()
{
    Response.ContentType = "text/css";
    return Content("Some content");
}
```

```html
<link rel="stylesheet" href="~/cacheTest.css" />
```

Open the page in chrome while viewing the Network developer tab, making sure Disable Cache is unticked. Reload the page or click on another page within your site and you can see the regular static files are loaded from the cache, but our cacheTest.css is not:

![Chrome Network Tab](/assets/img/chrome_network.png)


This is because ASP.NET automatically adds a last-modified-by header for normal static files in the wwwroot folder, but not for files created dynamically with the Content() method.

### cache-control

The standard way the server controlling how the browser caches a resource is with the HTTP header [cache-control](https://varvy.com/pagespeed/cache-control.html).

A server can tell the browser to cache a resource and use it for a certain period of a time, by returning a response with cache-control max-age set:

![Cache Control Max Age Header](/assets/img/chrome_cache_control_header.png)

max-age is a value in seconds that the resource may be cached for. If a new request is made for the same resource within the max-age, the browser will use the cached resource.

To tell the browser it cannot cache the resource, and the next request must go back to the server, set the cache-control header to 'no-cache'

### E-tags

[E-tags](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/ETag) are another mechanism to increase page speed. An e-tag is an HTTP header with a unique value set by the server for each version of the resource. Usually it is an ID computed by hashing the file contents.

E-tags extend the functionality of cache-control by telling the browser that the previous version of the resource has not changed, and this previous version can be used instead of sending the entire resource over the network again.

If a new request is within the cache-control max-age, use the browser cached file. If it is beyond, send a new request with the E-tag value set in the if-none-match header.

On the server side, if this E-tag from the request matches the one computed on the file,
the server can respond with a short 304 not modified response, which tell the browser the file has not been modified, and it can use the previous version held in its cache. Returning a short 304 response is faster than sending the entire resource over the network again.

If the file content has changed, the e-tag computed on the file will be different, and the server responds with the new file with a new e-tag.
