using Microsoft.AspNetCore.Identity;
using MongoDB.Driver;
using System.ComponentModel;

namespace Store.MongoDb.Identity.Stores
{
    public class RoleStore<TRole, TKey> : IRoleStore<TRole>
        where TRole : IdentityRole<TKey>
        where TKey : IEquatable<TKey>
    {
        public IdentityErrorDescriber ErrorDescriber { get; set; }
        private readonly IMongoCollection<TRole> _collection;
        private bool _disposed;

        public RoleStore(IMongoCollection<TRole> collection, IdentityErrorDescriber describer)
        {
            _collection = collection;
            ErrorDescriber = describer ?? new();
        }
        protected void ThrowIfDisposed()
        {
            if (_disposed)
            {
                throw new ObjectDisposedException(GetType().Name);
            }
        }
        public void Dispose() => _disposed = true;

        public async Task<IdentityResult> CreateAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null) throw new ArgumentNullException(nameof(role));

            await _collection.InsertOneAsync(role, cancellationToken: cancellationToken).ConfigureAwait(false);

            return IdentityResult.Success;
        }

        public async Task<IdentityResult> DeleteAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null) throw new ArgumentNullException(nameof(role));

            var result = await _collection.DeleteOneAsync(x => x.Id.Equals(role.Id) && x.ConcurrencyStamp.Equals(role.ConcurrencyStamp), cancellationToken).ConfigureAwait(false);
            if (!result.IsAcknowledged || result.DeletedCount == 0)
            {
                return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
            }

            return IdentityResult.Success;
        }

        public Task<TRole?> FindByIdAsync(string roleId, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            return _collection.Find(x => x.Id.Equals(ConvertIdFromString(roleId))).FirstOrDefaultAsync();
        }

        public Task<TRole?> FindByNameAsync(string normalizedRoleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            return _collection.Find(x => x.NormalizedName == normalizedRoleName).FirstOrDefaultAsync();
        }

        public Task<string?> GetNormalizedRoleNameAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null) throw new ArgumentNullException(nameof(role));

            return Task.FromResult(role.NormalizedName);
        }

        public Task<string> GetRoleIdAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null) throw new ArgumentNullException(nameof(role));

            return Task.FromResult(ConvertIdToString(role.Id));
        }

        public Task<string?> GetRoleNameAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null) throw new ArgumentNullException(nameof(role));

            return Task.FromResult(role.Name);
        }

        public Task SetNormalizedRoleNameAsync(TRole role, string? normalizedName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null) throw new ArgumentNullException(nameof(role));

            role.NormalizedName = normalizedName;

            return Task.CompletedTask;
        }

        public Task SetRoleNameAsync(TRole role, string? roleName, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null) throw new ArgumentNullException(nameof(role));

            role.Name = roleName;

            return Task.CompletedTask;
        }

        public async Task<IdentityResult> UpdateAsync(TRole role, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ThrowIfDisposed();

            if (role == null) throw new ArgumentNullException(nameof(role));

            var currentConcurrencyStamp = role.ConcurrencyStamp;
            role.ConcurrencyStamp = Guid.NewGuid().ToString();

            var result = await _collection.ReplaceOneAsync(x => x.Id.Equals(role.Id) && x.ConcurrencyStamp.Equals(currentConcurrencyStamp), role, cancellationToken: cancellationToken).ConfigureAwait(false);

            if (!result.IsAcknowledged || result.ModifiedCount == 0)
            {
                return IdentityResult.Failed(ErrorDescriber.ConcurrencyFailure());
            }

            return IdentityResult.Success;
        }

        public virtual TKey ConvertIdFromString(string id)
        {
            if (id == null)
            {
                return default(TKey);
            }
            return (TKey)TypeDescriptor.GetConverter(typeof(TKey)).ConvertFromInvariantString(id);
        }

        public virtual string ConvertIdToString(TKey id)
        {
            if (Equals(id, default(TKey)))
            {
                return null;
            }
            return id.ToString();
        }
    }
}
