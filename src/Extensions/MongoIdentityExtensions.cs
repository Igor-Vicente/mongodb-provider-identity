using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Store.MongoDb.Identity.Models;
using Store.MongoDb.Identity.Models.Interfaces;
using Store.MongoDb.Identity.Stores;
using Store.MongoDb.Identity.Utils;

namespace Store.MongoDb.Identity.Extensions
{
    public static class MongoIdentityExtensions
    {
        public static IdentityBuilder AddIdentityMongoDbStores<TUser, TRole, TKey>(this IdentityBuilder builder, Action<MongoOptions> mongoDbOptions,
            IdentityErrorDescriber identityErrorDescriber = null!)
            where TKey : IEquatable<TKey>
            where TRole : MongoRole<TKey>
            where TUser : MongoUser<TKey>, IIdentityUserClaim, IIdentityUserRole
        {
            var dbOptions = new MongoOptions();
            mongoDbOptions(dbOptions);

            builder.AddUserStore<UserStore<TUser, TRole, TKey>>()
                .AddRoleStore<RoleStore<TRole, TKey>>()
                .AddUserManager<UserManager<TUser>>()
                .AddRoleManager<RoleManager<TRole>>();

            var userCollection = CollectionFactory.SetCollection<TUser>(dbOptions, dbOptions.UsersCollection);
            var roleCollection = CollectionFactory.SetCollection<TRole>(dbOptions, dbOptions.RolesCollection);

            builder.Services.AddSingleton(userCollection);
            builder.Services.AddSingleton(roleCollection);

            builder.Services.AddTransient<IUserStore<TUser>>(x => new UserStore<TUser, TRole, TKey>(userCollection, roleCollection, identityErrorDescriber));
            builder.Services.AddTransient<IRoleStore<TRole>>(x => new RoleStore<TRole, TKey>(roleCollection, identityErrorDescriber));

            return builder;
        }
    }
}
