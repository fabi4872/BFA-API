using BFASenado.DTO.LogDTO;

namespace BFASenado.Services
{
    public class LogService : ILogService
    {
        public LogDTO CrearLog(HttpContext context, object? datosRecibidos, string? mensaje, string? detalles)
        {
            // Truncar datos largos para evitar sobrecargar los logs
            var datosRecortados = datosRecibidos != null && datosRecibidos is string datosString && datosString.Length > 100
                ? datosString.Substring(0, 100) + "..."
                : datosRecibidos;

            // Crear el log con información relevante
            return new LogDTO
            {
                Endpoint = $"{context.Request.Path}",
                MetodoHttp = $"{context.Request.Method}",
                DatosRecibidos = datosRecortados, // Datos recortados o directamente los recibidos
                Mensaje = mensaje,
                Detalles = detalles
            };
        }
    }
}
