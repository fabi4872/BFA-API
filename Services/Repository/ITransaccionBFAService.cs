using BFASenado.Models;

namespace BFASenado.Services.Repository
{
    public interface ITransaccionBFAService
    {
        Task<IEnumerable<TransaccionBFA>> GetAll();
        Task<TransaccionBFA?> GetById(long id);
        Task<TransaccionBFA?> GetByHash(string hashSHA256);
        Task<bool> Save(TransaccionBFA transaccion);
        Task<bool> Update(TransaccionBFA transaccion);
    }
}
