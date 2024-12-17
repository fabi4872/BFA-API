using System.ComponentModel.DataAnnotations;

namespace BFASenado.DTO.RequestDTO
{
    public class RegistroRequestDTO
    {
        [Required(ErrorMessage = $"{Constantes.Constants.DataAnnotationsErrorMessages.Required}")]
        [Range(1, long.MaxValue, ErrorMessage = Constantes.Constants.DataAnnotationsErrorMessages.GreaterThanZero)]
        public long IdTabla { get; set; }

        [Required(ErrorMessage = $"{Constantes.Constants.DataAnnotationsErrorMessages.Required}")]
        [Range(1, long.MaxValue, ErrorMessage = Constantes.Constants.DataAnnotationsErrorMessages.GreaterThanZero)]
        public long IdOrigen { get; set; }

        [Required(ErrorMessage = $"{Constantes.Constants.DataAnnotationsErrorMessages.Required}")]
        public string NombreTabla { get; set; } = null!;

        [Required(ErrorMessage = $"{Constantes.Constants.DataAnnotationsErrorMessages.Required}")]
        public string TipoDocumento { get; set; } = null!;

        public string? Detalles { get; set; }
    }
}
