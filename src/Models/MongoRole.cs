using Microsoft.AspNetCore.Identity;
using MongoDB.Bson;

namespace Store.MongoDb.Identity.Models
{
    public class MongoRole : MongoRole<ObjectId>
    {
        public MongoRole() { }
        public MongoRole(string roleName) : base(roleName) { }
    }

    public class MongoRole<TKey> : IdentityRole<TKey> where TKey : IEquatable<TKey>
    {
        public MongoRole() { }
        public MongoRole(string roleName)
        {
            Name = roleName;
            NormalizedName = roleName.ToUpperInvariant();
        }
    }

}
