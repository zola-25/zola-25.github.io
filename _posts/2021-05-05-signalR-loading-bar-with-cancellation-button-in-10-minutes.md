---
title: "An ASP.NET Core loading bar with cancellation button using SignalR in 10 minutes"
permalink: /post/An-ASPNET-Core-loading-bar-with-cancellation-button-using-SignalR-in-10-minutes
layout: default
tags: SignalR loading-bar .net .netcore dotnetcore asp.netcore bootstrap
---

The aim here is to demonstrate the simplest way to use SignalR (Core version) in ASP.NET Core to create a loading bar that will automatically update itself whenever we push through SignalR the latest progress amount of a long running task to it.

I won't go into details of every function and class necessary here, it's just an example using only ASP.NET Core, JQuery, Bootstrap and SignalR.

![SignalR Loading Bar Demo](/assets/img/posts/signalR-loading-bar-in-10-minutes/signalR-loading-bar-in-10-minutes.png)

Starting from the default VS 2019 MVC template, add a new folder in the Web Project called SignalR.

Then add a class deriving from the SignalR Hub class that's used to push and receive communications from the client:

```csharp

using Microsoft.AspNetCore.SignalR;

namespace SignalRDemo.SignalR
{
    public class LoadingBarHub : Hub
    {
    }
}


```
Secondly, in the same folder, add a factory class that creates a [Progress<double>](https://docs.microsoft.com/en-us/dotnet/api/system.progress-1?view=net-5.0) (returned as an IProgress<double>) that defines the action to be done when you want to send an update to your progress bar.

With the LoadingBarHub we created above, it would look like this:

```csharp

using Microsoft.AspNetCore.SignalR;
using System;

namespace SignalRDemo.SignalR
{

    public interface IProgressReporterFactory
    {
        IProgress<double> GetLoadingBarReporter(string connectionId);
    }

    public class ProgressReporterFactory : IProgressReporterFactory
    {
        private readonly IHubContext<LoadingBarHub> _progressHubContext;

        public ProgressReporterFactory(IHubContext<LoadingBarHub> progressHubContext)
        {
            _progressHubContext = progressHubContext;
        }

        public IProgress<double> GetLoadingBarReporter(string connectionId)
        {
            if (connectionId == null)
            {
                // if no connection allow reporting of progress just don't do anything with it
                return new Progress<double>();
            }

            double fractionComplete = 0;
            IProgress<double> progress = new Progress<double>(fractionDone =>
            {
                fractionComplete += fractionDone;
                _progressHubContext.Clients.Client(connectionId).SendAsync("updateLoadingBar", fractionComplete);
            });

            return progress;
        }
    }
}

```

Now in our Models folder, we create the View Model LoadViewModel: 

```csharp

namespace SignalRDemo.Models
{
    public class LoadViewModel
    {
        public int Seconds { get; set; }

        public string ConnectionId { get; set; }
    }
}

```

and in our HomeController.cs we add the action method:

```csharp

public async Task<IActionResult> Load(LoadViewModel loadViewModel, CancellationToken cancellationToken)
{
    var progressReporter = _progressReporterFactory.GetLoadingBarReporter(loadViewModel.ConnectionId);

    for(int i = 0; i < loadViewModel.Seconds; i++)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return NoContent();
        }

        progressReporter.Report(1 / (double)loadViewModel.Seconds);
        await Task.Delay(1000);
    }

    return Content("Completed");

}

```

In our /Views/Home/Index.cshtml, we define a few form controls, and a [bootstrap progress bar](https://getbootstrap.com/docs/4.0/components/progress/), that will demo the real time updates from calling the `Load(LoadViewModel loadViewModel, CancellationToken cancellationToken)` action method.

```HTML+Razor

@model LoadViewModel

<div class="text-center">

    <div class="form-group">
        <label asp-for="Seconds">Number of Seconds</label>
        <input asp-for="Seconds" type="number" class="form-control" aria-describedby="emailHelp" min="1" step="1" value="20">
    </div>

    <button id="btn-load" type="button" class="btn btn-primary">Load</button>
    
    <div id="div-loading" class="div-loading text-center mt-5" style="display: none">

        <div class="progress mx-auto mt-5" style="max-width: 300px;">
            <div class="progress-bar bg-dark"
                 role="progressbar"
                 aria-valuemin="0"
                 aria-valuemax="100"
                 aria-valuenow="0">
            </div>
        </div>

        <div class="text-center mt-3 mb-3">
            <button type="button" id="loading-cancel" class="btn btn-sm btn-outline-secondary">Cancel</button>
        </div>
    </div>
    <br />
    <div id="final-result" class="mt-5">

    </div>

</div>

```

Then in our javascript file site.js, we define two [IIFE](https://developer.mozilla.org/en-US/docs/Glossary/IIFE) encapsulations, one specific to our loading bar home page with its form controls (`loadingBar`), the other a resusable IIFE that can be shared across your site whenever you need a loading bar - `loadingWithProgressAndAbort` (albeit needing a few tweaks, perhaps passing in different div ids for your loading bar and cancel button, if they change across pages):

```js

var loadingBar = (function () {

    $(document).ready(function () {

        $(document).on("click", "#btn-load", function (e) {

            $("#final-result").empty();

            let seconds = $("#Seconds").val();

            let dataModel = {
                seconds
            };

            let ajaxOptions = {
                type: "GET",
                data: dataModel,
                contentType: "application/json",
                traditional: true,
                url: "/Home/Load",
                success: function (result) {
                    $("#final-result").html(result);
                }
            };

            loadingWithProgressAndAbort.withSignalR(ajaxOptions);
        });
    });

})();


var loadingWithProgressAndAbort = (function () {

    function bindAbort(jqXHR) {

        $(document).on("click", "#loading-cancel", function () {
            jqXHR.abort();
            $("#final-result").html("Cancelled");
            enableLoadButton();
        });
    };

    function startLoading() {

        $("#div-loading").show();
    };

    function setProgress(progress) {

        $("#div-loading .progress-bar").attr("style", `width:${progress}%; transition:none;`);
        $("#div-loading .progress-bar").attr("aria-valuenow", progress);
        $("#div-loading .progress-bar").text(`${progress}% `);
    };

    function stopLoading() {

        $("#div-loading").hide();
        setProgress("#div-loading", 0);
    };

    function disableLoadButton() {

        let button = $("#btn-load");
        button.prop("disabled", true);
        button.addClass("disable-hover");
    };

    function enableLoadButton () {

        let button = $("#btn-load");
        button.prop("disabled", false);
        button.removeClass("disable-hover");

    };

    return {

        withSignalR: function (ajaxOptions) {

            disableLoadButton();

            var connection =
                new signalR.HubConnectionBuilder()
                    .withUrl("/loadingBarProgress")
                    .build();

            connection.on("updateLoadingBar",
                (perc) => {
                    var progress = Math.round(perc * 100);
                    setProgress(progress);
                });

            connection
                .start()
                .then(function () {

                    const connectionId = connection.connectionId;

                    if (ajaxOptions.data === undefined) {
                        ajaxOptions["data"] = {};
                    }
                    ajaxOptions.data["connectionId"] = connectionId;

                    const xhr = $.ajax(ajaxOptions);
                    bindAbort(xhr);
                    startLoading();

                    xhr.always(function () {
                        connection.stop();
                        stopLoading();
                        enableLoadButton();
                    });
                });
        }
    };

})();

```

Some non-template css just to style our loading bar and form controls:

```css

.div-loading {
    text-align: center;
}

.progress {
    max-width: 400px;
}

.disable-hover {
    pointer-events: none;
}

```

Then finally make sure we are referencing the SignalR Core client side library in our layout:

```html

<script src="https://cdnjs.cloudflare.com/ajax/libs/microsoft-signalr/3.1.3/signalr.js" integrity="sha384-PkPMygF8Tu3OBnsBJ1slmE0AJ4pToeAZR99L0r6Gh+RvDME9IF+k38lsRg/OYGw6" crossorigin="anonymous"></script>
    
```

And add the requisite libraries and configuration to our Startup.js:

```csharp

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using SignalRDemo.SignalR;

public void ConfigureServices(IServiceCollection services)
{
    services.AddTransient<IProgressReporterFactory, ProgressReporterFactory>();

    services.AddControllersWithViews().AddRazorRuntimeCompilation();

    services.AddSignalR();

}

public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
{

  ...
  
  app.UseEndpoints(endpoints =>
  {
      endpoints.MapControllerRoute(
          name: "default",
          pattern: "{controller=Home}/{action=Index}/{id?}");

      endpoints.MapHub<LoadingBarHub>("/loadingBarProgress");

  });
}
```

And that's it. Our loading bar will take as long to crawl across the screen as the number of seconds we give it. If we click the cancel button, it will notify the `CancellationToken` we passed to our action method that our long running process is cancelled and to exit early from the action method. 

The CancellationToken can be passed down into other class methods and View Components, so the user always has the ability to cancel a long running process. Also, if they navigate away from the site page while the long process is still executing, the `CancellationToken` will be activated and the action method exited, freeing up computational or thread resources.

[Full example project here](https://github.com/zola-25/SignalR-LoadingBar-Demo)

