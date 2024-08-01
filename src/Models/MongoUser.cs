
using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;
using Store.MongoDb.Identity.Models.Interfaces;

namespace Store.MongoDb.Identity.Models
{
    public class MongoUser : MongoUser<ObjectId>, IIdentityUserClaim, IIdentityUserRole, IIdentityUserLogin
    {
        public MongoUser() { }
        public MongoUser(string userName) : base(userName) { }
    }


    public class MongoUser<TKey> : IdentityUser<TKey> where TKey : IEquatable<TKey>
    {
        public MongoUser()
        {
        }
        public MongoUser(string userName)
        {
            UserName = userName;
            NormalizedUserName = userName.ToUpperInvariant();
        }
        public List<string> Roles { get; set; } = new();

        public List<IdentityUserClaim<string>> Claims { get; set; } = new();

        public List<IdentityUserLogin<string>> Logins { get; set; } = new();
    }
}
