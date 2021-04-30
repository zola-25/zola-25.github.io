---
title: "A template for handling Asynchronous REST Operations in R Plumber"
permalink: /post/a-template-for-handling-asynchronous-rest-operations-in-r-plumber
layout: default
tags: R plumber REST asynchronous 
---

<div style="text-align: center">
  <h3> Serve concurrent requests with R plumber without creating multiple instances with complex load balancing solutions </h3>
</div>

### The single-threading Problem

R Plumber is great for easily opening your R analytics to other services to access via HTTP. If you’ve got a web application front end that serves analytics results to the client for example, there maybe be some processing that really can only be done with a specific R library, such as fitting and predicting from niche machine learning models. Not to mention the current trend towards micro-service architecture makes it essential that services can respond to HTTP requests within a cloud environment.

The biggest problem you encounter when working with R Plumber is that it is, like R, single threaded, meaning for plumber it can only deal with one request at a time. Likely your API requests will need to perform some long running analysis or model fitting, meaning every other request must wait until the next one has finished before it can be processed. If you’re trying to build a multi-user application, this is a huge roadblock.

There are a number of solutions for this single-threaded issue, which R Plumber [have detailed very well in their documentation](https://www.rplumber.io/docs/hosting.html). One involves paying for RStudio Connect, another involves containerizing your R Plumber app and running it on a machine with docker-compose, which is quite a lot of leg work if you’re short on time or aren’t up to speed with docker, or even if you have already containerized your plumber application and are hosting it as a single-container application in your cloud service, but scaling out to multi-containers with load balancing means substantial cloud architecture changes or price increases.

However there is a little-discussed middle-of-the-road option that avoids this extra architecture setup, at the expense of changing your API interface to use an [asynchronous request-reply pattern](https://docs.microsoft.com/en-us/azure/architecture/patterns/async-request-reply), despite R Plumber only ever running one request/response thread. To summarize, this pattern involves clients POSTing requests for resources to begin processing or creating. A separate task is then spawned in the background that begins the long running process of creating the resource. The API then returns a response indicating the status location where the client can keep polling to find out if the resource has been completed. Once the task is completed, the polling location returns a redirect to the completed resource location, where the completed resource is returned.

This pattern is ideal for many R Plumber scenarios are often we are only using R to perform some time-consuming analysis. It also solves the problem of a fixed timeout some cloud providers enforce on HTTP request processing when using their hosting. For example, Azure App Services [will timeout requests after 4 minutes](https://stackoverflow.com/questions/32755403/increase-azure-web-app-request-timeout), with no option for the user to increase this setting, other than moving to their own VM.

Implementation

The key to allowing this pattern in R Plumber is to make use of the [future](https://rstudio.github.io/promises/articles/futures.html) package. Briefly, the future package is like a Task in .NET, in that you can perform some action asynchronously, outside of the main executing thread, and in R this means in a separate process.

Normally our R Plumber GET request endpoint for a long running analysis might look something like this:

```R
  # plumber_synchronous.R

  source("./analysis.R")


  #' Get then analysis result for the provided <analysisId>
  #' @serializer unboxedJSON
  #' @get /analysis/<analysisId>/result
  function(analysisId){

    analysisResult <- runAnalysis(analysisId)

    return(analysisResult)

  }
```

Given that runAnalysis takes a long time, this stops any other requests being handled until it has finished.

Instead we replace this GET request handler with a POST request handler that creates a future with the work of running the analysis.

```R
  # plumber.R
  require(future)
  require(uuid)

  plan(multiprocess)


  defaultPackages <- c("plyr",
                         "dplyr",
                         "dbplyr",
                         "reshape2",
                         "neuralnet",
                         ...whatever you need)

  defaultGlobals <- c("workingDir")

  workingDir <- getwd()

  executingFutures <- list()
  completedFutures <- list()


  #' Being an asynchronous analysis for the provided <analysisId>
  #' @serializer unboxedJSON
  #' @post /analysis/<analysisId>/run
  function(res, analysisId){

    analysisId <- as.integer(analysisId)

    uniqueId <- UUIDgenerate()

    f <- future(
      {
          setwd(workingDir)
          source("./analysis.R")

          analysisResult <- runAnalysis(analysisId) # Run anything you like as long as it is in a package or sourced

          return(list(
                  completedLocation=paste0("/resource/", uniqueId, "/result"),
                  result=analysisResult))
      }, 
      globals=c(defaultGlobals,
                "analysisId",
                "uniqueId"), 
      packages=c(defaultPackages)
    )


    executingFutures[[as.character(uniqueId)]] <<- f

    return(resourceAcceptedResponse(res, uniqueId))

  }

  resourceAcceptedResponse <- function(res, uniqueId) {

    queueLocation <- paste0("/queuedResource/", uniqueId, "/status")
    res$status <- 202
    res$setHeader("location", queueLocation)
    return(list(message=paste0("This resource is being created. Keep checking back at GET ", queueLocation, ", when completed you will be redirected to the completed resource"),
                location=queueLocation))
  }
```

The POST request handler gives each analysis request a unique GUID/UUID, and keeps track of the executing analyses by storing them in a global variable, executingFutures.

It then responds with a 202 status code, used [for indicating that request has been accepted for processing, but the processing has not been completed](https://restfulapi.net/http-status-202-accepted/), and with the location which the client can keep checking to get the status of the executing analysis.

```R
#' @serializer unboxedJSON
#' @get /queuedResource/<uniqueId>/status
function(res, uniqueId){

  executingFuture <- executingFutures[[uniqueId]]
  if(!is.null(executingFuture)){
    
    if(resolved(executingFuture)) {
      
      #executingFuture is no longer executing and has resolved!
      
      # move from executing to resolved list
      executingFutures[[as.character(uniqueId)]] <<- NULL
      completedFutures[[as.character(uniqueId)]] <<- executingFuture
      
      return(resourceCompletedRedirect(res, executingFuture))
      
    } else {
    
    
      # still executing
      return(resourceAcceptedResponse(res, uniqueId))
    }
  }
    
  resolvedFuture <- completedFutures[[uniqueId]]
  
  if(is.null(resolvedFuture)) {
    
    return(resourceNotFoundResponse(res, uniqueId))
  }
  
  return(resourceCompletedRedirect(res, resolvedFuture))
}



resourceCompletedRedirect <- function (res, f) {
  
  futureValue <- value(f)
  res$setHeader("location", futureValue$completedLocation)
  res$status <- 303 
  return(list(message=paste0("Redirecting to completed resource location ", futureValue$completedLocation),
              location=futureValue$completedLocation))
}


resourceNotFoundResponse <- function(res, uniqueId) {

  res$status <- 404
  return(list(message=paste0("Resource with ID ", uniqueId, " not found. Cache may have expired, please try recreating the resource.")
    ))
}
```

Because each analysis has been given a unique ID, the client can check the status of it by calling GET /queuedResource/{uniqueId}/status.

If the future is still executing, it replies back with the same 202 status, so the client knows to keep checking back. If it has completed, it moves the future off the executingFutures list and on to the completedFutures list. It then returns a 303 redirect status code, along setting the location head with the location of the completed resource. Finally, we define the endpoint where completed resources can be accessed:

```R
#' @serializer unboxedJSON
#' @get /resource/<uniqueId>/result
function(res, uniqueId){
  
  if(is.null(uniqueId)) {
    res$status = 404
    return(list(message="{uniqueId} not provided. Format is GET /resource/{uniqueId}/result to retrieve completed resources"
                ))
  }
  
  f <- completedFutures[[as.character(uniqueId)]]
  if(is.null(f))
  {
    return(resourceNotFoundResponse(res, uniqueId))
  }
  
  return (value(f)$result)
}
```

And that’s it, an Asynchronous REST API with R Plumber. Note that I said this API serves concurrent requests - this isn’t strictly true, as the R Plumber request handling is still single threaded and can only serve one request at a time. But because each request returns very quickly as it only has to either start the future, return the future status or return the future results, the blocking time is much shorter compared to running the analysis synchronously.

[Full code](https://gist.github.com/zola-25/ddfd45719fc69d3d987ab63c49790897)
