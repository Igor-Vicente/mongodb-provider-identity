using MongoDB.Driver;

namespace Store.MongoDb.Identity.Utils
{
    public static class CollectionFactory
    {
        public static IMongoCollection<TItem> SetCollection<TItem>(MongoOptions options, string collectionName)
        {
            var client = new MongoClient();
            var db = client.GetDatabase(options.DatabaseName);
            return db.GetCollection<TItem>(collectionName);
        }
    }
}
