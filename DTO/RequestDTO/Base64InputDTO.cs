using System.ComponentModel.DataAnnotations;

namespace BFASenado.DTO.RequestDTO
{
    public class Base64InputDTO
    {
        [Required(ErrorMessage = $"{Constantes.Constants.DataAnnotationsErrorMessages.Required}")]
        [RegularExpression("^[A-Za-z0-9+/]+={0,2}$", ErrorMessage = $"{Constantes.Constants.DataAnnotationsErrorMessages.FormatoIncorrecto}")]
        public string Base64 { get; set; } = null!;
    }
}
