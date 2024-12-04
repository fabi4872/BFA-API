using BFASenado.DTO.ResponseDTO;

namespace BFASenado.Services.BFA
{
    public interface IBFAService
    {
        Task<bool> IsNodeAvailable();
        Task<bool> IsNodeSynced();
        Task<GetHashDTO?> GetHashDTO(string hash);
        string CalcularHashSHA256(byte[] fileBytes);
    }
}
