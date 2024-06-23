using Microsoft.AspNetCore.Identity;

namespace Store.MongoDb.Identity.Models.Interfaces
{
    public interface IIdentityUserClaim
    {
        List<IdentityUserClaim<string>> Claims { get; set; }
    }
}
