using BFASenado.DTO.LogDTO;

namespace BFASenado.Services
{
    public class LogService : ILogService
    {
        public LogDTO CrearLog(HttpContext context, object? datosRecibidos, string? mensaje, string? detalles)
        {
            return new LogDTO
            {
                Endpoint = $"{context.Request.Path}",
                MetodoHttp = $"{context.Request.Method}",
                DatosRecibidos = datosRecibidos,
                Mensaje = mensaje,
                Detalles = detalles
            };
        }
    }
}
