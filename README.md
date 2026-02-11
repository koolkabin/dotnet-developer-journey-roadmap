# dotnet-developer-journey-roadmap
dotnet-developer-journey-roadmap

# must have basic repos
- identity framework: for login and authentication with RABC
- entity framework: for database related stuffs esp. mssql

# security related packages that we must have
- JWT auth package: to make sure only authorized users have access to our protected resources
- api rate limit: for blocking large no of request from single ip in short interval of time which may be security issue

# packages that we love to implement
- grafana/serilo: for logging user behaviour and application logs
- nepali calendar: for date conversion between nepali and english
- hangfire: for making and running background josb
- repobasemodelcore: for generic actions of our db related models

# patterns what we love to work:
- CQRS Pattern: to separate request/response models from databasse models
- Repo pattern: to make our db operations easy and have a topping layer above dbcontext
- outbox pattern: to send email notification, upload files to google drive, cloudflare r2 storage etc without holding back response to users,

# must know
- request running pipelines: server -> middleware -> controller -> actions flow

# Addition Development
- middleware development
- delegate handling
- event driven approach
- 
