namespace Store.MongoDb.Identity.Models.Interfaces
{
    public interface IIdentityUserRole
    {
        public List<string> Roles { get; set; }
    }
}
