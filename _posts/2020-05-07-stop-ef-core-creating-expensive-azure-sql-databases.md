---
title: "Stop EF Core creating expensive Azure SQL Database configurations on start up"
permalink: /post/stop-ef-core-creating-expensive-azure-sql-databases
tags: ef-core azure sql git
---

<div style="text-align: center;"> 
# Stop EF Core creating expensive Azure SQL Database configurations on start up

{{ page.date | date: '%B %d, %Y' }}
</div>

If you're developing an application that uses Azure SQL Databases for development and testing, you usually just want the bare minimum configuration, the Basic or Standard options, so you don't waste cash.

If you're using EF Core as your ORM and you automatically run migrations on startup, if it doesn't find the database on the server specified in your connection string, it will automatically create the database for you. This is great if you're working on a development branch of your codebase and you need a separate database for your work.

However, the default Azure database configuration that EF Core will create is the vCore General Purpose Generation 5 which comes out at 320+ £/month!

Here's something that you can call in your application startup that will avoid that. It checks your connection string for the database you are trying to connect to, and if it doesn't exist, creates it as a Standard configuration that is priced at the more managable £13.98/month. In my experience Basic is sometimes too slow even for development, so the Standard option is usually my first choice.  

```cs 
using System.Data.SqlClient;
using System.Linq;


public interface IDevelopmentDatabaseCreator
{
	void CreateDevelopmentDatabase(string connectionString);
}


public class DevelopmentDatabaseCreator : IDevelopmentDatabaseCreator
{
	public void CreateDevelopmentDatabase(string connectionString)
	{
		var builder = new SqlConnectionStringBuilder(connectionString);
		string dbToCreate = builder.InitialCatalog;

		string masterDbConnectionString = connectionString.Replace(dbToCreate, "master"); // Ideally would use the SqlConnectionStringBuilder to just replace the db name with master, but when the ConnectionString property is called on the builder it always returns a connection string with a DataSource=... property instead of Server=..., which for some reason doesn't work on Azure

		using (var conn = new SqlConnection(masterDbConnectionString))
		{
			conn.Open();
			using (var command = new SqlCommand())
			{
				command.Connection = conn;
				CheckDbName(dbToCreate); // You can't use parameters when using SQL DDL like CREATE DATABASE, so have to validate SQL manually
				command.CommandTimeout = 60;
				command.CommandText = $@" 

				IF NOT EXISTS (SELECT * FROM sys.databases WHERE name = '{dbToCreate}')
				BEGIN
					CREATE DATABASE [{dbToCreate}] (
					MAXSIZE=2 GB,
					EDITION='Standard',
					SERVICE_OBJECTIVE='S0') 
				END";

				command.ExecuteNonQuery();
			}
		}
	}

	private void CheckDbName(string dbName)
	{
		if (dbName.Any(c =&gt; !(Char.IsLetterOrDigit(c) || c == '-')))
		{
			throw new Exception("DB name is invalid");
		}
	}
}
```

Then, in your Startup.cs file if you're running ASP.NET Core, you can make sure it's always called before you call `dbContext.Database.Migrate()` or `dbContext.Database.EnsureCreated()`:

```cs
public class Startup
{
	public Startup(IConfiguration configuration, IHostingEnvironment appEnv)
	{
		_configuration = configuration;
		_currentEnvironment = appEnv;
	}

	private IConfiguration _configuration;

	private IHostingEnvironment _currentEnvironment;

	public void ConfigureServices(IServiceCollection services)
	{
		///...		
		services.AddTransient<IDevelopmentDatabaseCreator, DevelopmentDatabaseCreator>();
		
		string connString = _configuration.GetConnectionString("YOUR_CONNECTIONSTRING");
		services.AddDbContext<AppDbContext>(o =>
			o.UseSqlServer(
				connString
			));
		
	}
	
	public void Configure(IApplicationBuilder app, AppDbContext dbContext, IDevelopmentDatabaseCreator devDatabaseCreator)
	{
		// ..after the rest of your app configuration:
		
		if(_currentEnvironment.IsDevelopment()) 
		{
			string connString = configuration.GetConnectionString("YOUR_CONNECTIONSTRING");
			devDatabaseCreator.CreateDevelopmentDatabase(connString); 
		}
		
		dbContext.Database.Migrate();

	}

}

```

Note that because the SQL script we are running is Data Definition Language rather thans standard SQL, we can't use Sql parameters pass through the DB name to create to the script (.NET doesn't support it). So to protect against SQL injection attacks, incase anyone manages to get malicious code into our connection string database name, we check the database name with `CheckDbName`.

## Addendum: Autosetting your connection string based on your Git branch

Most dev teams need to create separate environments for their git branches, where the application is hosted based on the branched code with a separate branch database, so testers, product owners and any other stakeholders can see a working demo of the latest feature.

Devs constantly switching branches when debugging locally is part of life, but we also have to remember to change the application connection string. So often we forget, in the best case leading to a start up error so we quickly realise our mistake, in the worst cases causing us to waste time wondering why we're not getting the results we expect, or even accidentally running database scripts and migrations into the wrong branch!

If you're running Git, here's a way in ASP.NET Core to automatically set your connection string based on what branch you are set to. Usually for consistency dev branch DBs will be named based on the branch name, so if you you know your git branch name you know your dev branch environment DB.

(Disclaimer: I'm pretty agnostic when it comes to version control systems, especially the merits of Git vs SVN, I don't think Git is all it's cracked up to be, but that's a debate for another time. Most teams have moved towards Git so I've moved with them :) )

The cruicial part is calling git from the command line through your application to get the git branch name, which I've copied from [this stack overflow answer](https://stackoverflow.com/questions/48421697/get-name-of-branch-into-code) that deserves more upvotes: 

```cs 

using System;
using System.Diagnostics;

public interface IGitBranchFinder
{
	string GetFullBranchName();
	string GetBranchNameLastPart();
}

public class GitBranchFinder : IGitBranchFinder
{
	public string GetFullBranchName()
	{
		ProcessStartInfo startInfo = new ProcessStartInfo("git.exe");

		startInfo.UseShellExecute = false;
		startInfo.WorkingDirectory = Environment.CurrentDirectory;
		startInfo.RedirectStandardInput = true;
		startInfo.RedirectStandardOutput = true;
		startInfo.Arguments = "rev-parse --abbrev-ref HEAD";

		using (var process = new Process())
		{
			process.StartInfo = startInfo;
			process.Start();

			string branchname = process.StandardOutput.ReadLine();

			return branchname;
		}
	}

	public string GetBranchNameLastPart()
	{
		string fullBranchName = GetFullBranchName();
		return fullBranchName.Contains("/") ? fullBranchName.Remove(0, fullBranchName.LastIndexOf('/') + 1) : fullBranchName;
	}
}

```

`GetBranchNameLastPart` is to deal with the fact that often Git branches are prefixed with feature/ or bug/ with the forward slash which is an invalid character for a SQL DB name, so we only use the last part for the DB name.

So then we can encapsulate some logic to get the application connection string to use in Startup.cs, that will always provide us with the right connection string based on our environment. In cloud hosted production and development environments we are likely to have the connection string specified in an app setting or environment variable, and we wouldn't (or couldn't) run git.exe from a hosted environment. So we check if there is any connection string setting specified, and if not, and we're running in a local environment, we work out the connection string automatically based on the `GitBranchFinder` we defined above. It's often convenient to define a 'Local' environment, which means a dev debugging the code locally, and a Development environment, which means a hosted development branch environment:

```cs 
using Enis.Domain.Abstractions.StartupServices;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;

public interface IConnectionStringBuilder
{
	string GetApplicationConnectionString();
}

public class ConnectionStringBuilder : IConnectionStringBuilder
{
	private readonly IConfiguration _configuration;
	private readonly IHostingEnvironment _hostingEnvironment;
	private readonly IGitBranchFinder _gitBranchFinder;

	public ConnectionStringBuilder(IConfiguration configuration, IHostingEnvironment hostingEnvironment, IGitBranchFinder gitBranchFinder)
	{
		_configuration = configuration;
		_hostingEnvironment = hostingEnvironment;
		_gitBranchFinder = gitBranchFinder;
	}

	public string GetApplicationConnectionString()
	{
		string connString = _configuration.GetConnectionString("YOUR_CONNECTION_STRING_APPSETTING"); ;

		// If no connection string set in Environment Variables or app setttings, and running locally, work out the connection string based on the branch name:
		if (connString == null && _hostingEnvironment.IsEnvironment("Local"))
		{
			connString = GetDevelopmentDatabaseConnectionString();
		}

		return connString;
	}

	private string GetDevelopmentDatabaseConnectionString()
	{
		string branchNameLastPart = _gitBranchFinder.GetBranchNameLastPart();
		string password = _configuration.GetValue<string>("YOUR_DEV_SQL_SERVER_PASSWORD")
		return 
			$"Server=tcp:[*your Azure Dev SQL Server*].database.windows.net,1433;Initial Catalog=[*your dev DB prefix convention*]-{branchNameLastPart};Persist Security Info=False;User ID=[*your-user-id*];Password={password};MultipleActiveResultSets=False;Encrypt=True;TrustServerCertificate=False;Connection Timeout=30;";            
	}
}
```

Then our Startup.cs file might look more like this:

```cs 
public class Startup
{
	public Startup(IConfiguration configuration, IHostingEnvironment appEnv)
	{
		_configuration = configuration;
		_currentEnvironment = appEnv;
	}

	public IConfiguration _configuration;

	private IHostingEnvironment _currentEnvironment { get; set; }


	public void ConfigureServices(IServiceCollection services)
	{
		
		//Startup services
		services.AddSingleton<IHostingEnvironment>(_currentEnvironment);
		services.AddTransient<IConnectionStringBuilder, ConnectionStringBuilder>();
		services.AddTransient<IGitBranchFinder, GitBranchFinder>();
		services.AddTransient<IDevelopmentDatabaseCreator, DevelopmentDatabaseCreator>();

		var sp = services.BuildServiceProvider();

		var connectionStringBuilder = sp.GetService<IConnectionStringBuilder>();
		var connString = connectionStringBuilder.GetApplicationConnectionString();
		

		services.AddDbContext<AppDbContext>(o =>
			o.UseSqlServer(
				connString
			));
		

	}


	public void Configure(IApplicationBuilder app, AppDbContext dbContext, IDevelopmentDatabaseCreator devDatabaseCreator, IConnectionStringBuilder connectionStringBuilder)
	{
		// ...after the rest of your app configuration:
		if(_currentEnvironment.IsDevelopment() || _currentEnvironment.IsEnvironment("Local")) 
		{
			var connString = connectionStringBuilder.GetApplicationConnectionString();
			devDatabaseCreator.CreateDevelopmentDatabase(connString); 
		}
		
		dbContext.Database.Migrate();
		
	}
}
```

[Full code here](https://gist.github.com/zola-25/2a006d269efa309d312655f1256fb2a5)

