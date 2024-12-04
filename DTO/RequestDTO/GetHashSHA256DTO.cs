using System.ComponentModel.DataAnnotations;

namespace BFASenado.DTO.RequestDTO
{
    public class GetHashSHA256DTO
    {
        [Required(ErrorMessage = $"{Constantes.Constants.DataAnnotationsErrorMessages.Required}")]
        [StringLength(64, MinimumLength = 64, ErrorMessage = $"{Constantes.Constants.DataAnnotationsErrorMessages.HashSHA256Length}")]
        [RegularExpression("^[a-fA-F0-9]{64}$", ErrorMessage = $"{Constantes.Constants.DataAnnotationsErrorMessages.FormatoIncorrecto}")]
        public string HashSHA256 { get; set; } = null!;
    }
}
