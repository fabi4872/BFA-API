using System.ComponentModel.DataAnnotations;

namespace BFASenado.DTO.HashDTO
{
    public class GuardarHashDTO
    {
        [Required(ErrorMessage = "El campo es obligatorio.")]
        public string? Hash { get; set; }

        [Required(ErrorMessage = "El campo es obligatorio.")]
        public string? Base64 { get; set; }
    }
}
