namespace BFASenado.DTO.ResponseDTO
{
    public class GetHashDTO
    {
        public string IdTabla { get; set; } = null!;
        public string NombreTabla { get; set; } = null!;
        public string NumeroBloque { get; set; } = null!;
        public string Hash { get; set; } = null!;
        public string Sellador { get; set; } = null!;
        public DateTime FechaAlta { get; set; }
        public string TipoDocumento { get; set; } = null!;
        public string? Detalles { get; set; }
        public string? Base64 { get; set; }
    }
}
