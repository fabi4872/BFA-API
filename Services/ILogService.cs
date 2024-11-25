using BFASenado.DTO.LogDTO;

namespace BFASenado.Services
{
    public interface ILogService
    {
        LogDTO CrearLog(HttpContext context, object? datosRecibidos, string? mensaje, string? detalles);
    }
}
