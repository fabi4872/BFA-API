using System.ComponentModel.DataAnnotations;

namespace BFASenado.DTO.RequestDTO
{
    public class GuardarHashDTO
    {
        [Required(ErrorMessage = $"{Constantes.Constants.DataAnnotationsErrorMessages.Required}")]
        [Range(1, long.MaxValue, ErrorMessage = Constantes.Constants.DataAnnotationsErrorMessages.GreaterThanZero)]
        public long IdTabla { get; set; }

        [Required(ErrorMessage = $"{Constantes.Constants.DataAnnotationsErrorMessages.Required}")]
        public string NombreTabla { get; set; } = null!;

        [Required(ErrorMessage = $"{Constantes.Constants.DataAnnotationsErrorMessages.Required}")]
        public string TipoDocumento { get; set; } = null!;

        [Required(ErrorMessage = $"{Constantes.Constants.DataAnnotationsErrorMessages.Required}")]
        [StringLength(64, MinimumLength = 64, ErrorMessage = $"{Constantes.Constants.DataAnnotationsErrorMessages.HashSHA256Length}")]
        [RegularExpression("^[a-fA-F0-9]{64}$", ErrorMessage = $"{Constantes.Constants.DataAnnotationsErrorMessages.FormatoIncorrecto}")]
        public string HashSHA256 { get; set; } = null!;

        [Required(ErrorMessage = $"{Constantes.Constants.DataAnnotationsErrorMessages.Required}")]
        [RegularExpression("^[A-Za-z0-9+/]+={0,2}$", ErrorMessage = $"{Constantes.Constants.DataAnnotationsErrorMessages.FormatoIncorrecto}")]
        public string Base64 { get; set; } = null!;

        public string? Detalles { get; set; }
    }
}
