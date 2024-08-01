using Microsoft.AspNetCore.Identity;

namespace Store.MongoDb.Identity.Models.Interfaces
{
    public interface IIdentityUserLogin
    {
        public List<IdentityUserLogin<string>> Logins { get; set; }
    }
}
