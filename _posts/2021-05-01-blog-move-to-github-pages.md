---
title: "Blog move to GitHub Pages"
permalink: /post/blog-move-to-github-pages
layout: default
tags: blog github githubpages azure
---

I've moved my blog from my ASP.NET Core site to a static file site hosted with GitHub Pages. 

The main reason - GitHub Pages offers free hosting, and free SSL certificates for custom domains using [Let's Encrypt](https://letsencrypt.org/). 

My ASP.NET Core site hosted on Azure needed a backend database and a non-free App Service plan to allow a custom domain. Especially given the very poor performance of the lowest database tier, the price per month could reach ~£25 with VAT, not even including the SSL certificate, which costs ~£50 a year. It is possible to [setup and automate the renewel](https://www.hanselman.com/blog/securing-an-azure-app-service-website-under-ssl-in-minutes-with-lets-encrypt) of a Let's Encrypt certificate on Azure, but this only solved the SSL cost.

GitHub Pages uses the static site generator Jekyll as its engine. Jekyll uses Ruby and has been around for a while, I was hesitant to use it at first due to Windows compatibility problems with Ruby and it seeming like an unnecessary extra layer of abstraction (a framework and language for blogging? really??). But GitHub Pages has placed it largely behind the scenes, and builds the site in it's own GitHub cloud environment, so there's no need to install Jekyll to build locally.

I put some effort into my ASP.NET Blog site so it's sad to move on, despite only creating a handful of posts with it. It includes features like  an admin section for creating your own blog posts with TinyMCE, syntax highlighting, and a search function. So if anyone wants to use it for their own purposes, it's still held [here](https://github.com/zola-25/Blog-ASP.NET-Core) :)



