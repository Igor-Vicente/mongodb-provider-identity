# mongo-identity

- I'm adding the interfaces and customizing it as needed.
- https://learn.microsoft.com/pt-br/aspnet/core/security/authentication/identity-custom-storage-providers?view=aspnetcore-8.0

## Adding to application:

```c#
services.AddIdentity<MongoUser, MongoRole>()
   .AddIdentityMongoDbStores<MongoUser, MongoRole, ObjectId>(o =>
   {
       o.ConnectionString = mongoSettings.ConnectionString;
       o.DatabaseName = mongoSettings.DatabaseName;
       o.UsersCollection = mongoSettings.UsersCollection;
       o.RolesCollection = mongoSettings.RolesCollection;
   });
```

### Publishing manaully \*.nupkg (Nuget Package)

- Add or Adjust the Code
- Define the version of the package (\*.csproj), Sample: <Version>x.x.xx</Version>
- Commit and Push the changes
- Generate the package

```c#
  dotnet pack
```

- publish the \*.nupkg generated
- option: https://www.nuget.org
