namespace Store.MongoDb.Identity.Utils
{
    public class MongoOptions
    {
        public string DatabaseName { get; set; } = "Identity";
        public string ConnectionString { get; set; } = "mongodb://localhost:27017/";
        public string UsersCollection { get; set; } = "Users";
        public string RolesCollection { get; set; } = "Roles";
    }
}
