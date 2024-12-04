using BFASenado.Models;
using Microsoft.EntityFrameworkCore;

namespace BFASenado.Services.Repository
{
    public class TransaccionBFAService : ITransaccionBFAService
    {
        #region Attributes

        // DB
        private readonly BFAContext _context;

        #endregion

        #region Constructor

        public TransaccionBFAService(BFAContext context)
        {
            _context = context;
        }

        #endregion

        #region Methods

        public async Task<IEnumerable<TransaccionBFA>> GetAll()
        {
            return await _context.Transacciones.ToListAsync();
        }

        public async Task<TransaccionBFA?> GetById(long id)
        {
            return await _context.Transacciones.FirstOrDefaultAsync(x => x.Id == id);
        }

        public async Task<TransaccionBFA?> GetByHash(string hashSHA256)
        {
            return await _context.Transacciones.FirstOrDefaultAsync(x => x.HashSHA256 == hashSHA256);
        }

        public async Task<bool> Save(TransaccionBFA transaccion)
        {
            try
            {
                _context.Transacciones.Add(transaccion);
                await _context.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                throw new Exception($"{Constantes.Constants.LogMessages.DBGuardarError}. {ex.Message}", ex);
            }
        }

        public async Task<bool> Update(TransaccionBFA transaccion)
        {
            try
            {
                _context.Transacciones.Update(transaccion);
                await _context.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                throw new Exception($"{Constantes.Constants.LogMessages.DBActualizarError}. {ex.Message}", ex);
            }
        }

        #endregion
    }
}
