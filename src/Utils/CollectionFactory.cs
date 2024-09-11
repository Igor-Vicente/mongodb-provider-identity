using MongoDB.Driver;

namespace Store.MongoDb.Identity.Utils
{
    public static class CollectionFactory
    {
        public static IMongoCollection<TItem> SetCollection<TItem>(MongoOptions options, string collectionName)
        {
            IMongoCollection<TItem> collection;
            var type = typeof(TItem);

            var url = new MongoUrl(options.ConnectionString);
            var settings = MongoClientSettings.FromUrl(url);
            var databaseName = url.DatabaseName ?? options.DatabaseName;

            settings.SslSettings = options.SslSettings;
            settings.ClusterConfigurator = options.ClusterConfigurator;

            var client = new MongoClient(settings);
            collection = client.GetDatabase(databaseName)
                .GetCollection<TItem>(collectionName ?? type.Name.ToLowerInvariant());

            return collection;
        }
    }
}
