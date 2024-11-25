namespace BFASenado.DTO.LogDTO
{
    public class LogDTO
    {
        public DateTime Fecha { get; set; } = DateTime.Now;
        public string? Endpoint { get; set; } // Nombre del endpoint
        public string? MetodoHttp { get; set; } // GET, POST, etc.
        public object? DatosRecibidos { get; set; } // Datos enviados por el usuario (query, body, etc.)
        public string? Mensaje { get; set; } // Mensaje del log (Info/Error)
        public string? Detalles { get; set; } // Detalles adicionales (como el stack trace)
    }
}
