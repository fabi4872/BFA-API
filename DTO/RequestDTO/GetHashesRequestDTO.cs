using System.ComponentModel.DataAnnotations;

namespace BFASenado.DTO.RequestDTO
{
    public class GetHashesRequestDTO
    {
        [StringLength(64, MinimumLength = 64, ErrorMessage = $"{Constantes.Constants.DataAnnotationsErrorMessages.HashSHA256Length}")]
        [RegularExpression("^[a-fA-F0-9]{64}$", ErrorMessage = $"{Constantes.Constants.DataAnnotationsErrorMessages.FormatoIncorrecto}")]
        public string? HashSHA256 { get; set; }

        [Range(0, long.MaxValue, ErrorMessage = Constantes.Constants.DataAnnotationsErrorMessages.GreaterThanZero)]
        public long? IdTabla { get; set; }

        [Range(0, long.MaxValue, ErrorMessage = Constantes.Constants.DataAnnotationsErrorMessages.GreaterThanZero)]
        public long? IdOrigen { get; set; }

        public string? NombreTabla { get; set; }
        public string? TipoDocumento { get; set; }
    }
}
