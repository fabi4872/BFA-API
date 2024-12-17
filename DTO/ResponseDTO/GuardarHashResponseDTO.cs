namespace BFASenado.DTO.ResponseDTO
{
    public class GuardarHashResponseDTO
    {
        public bool? SnSaveBaseDatos { get; set; } = false;
        public bool? SnSaveBFA { get; set; } = false;
        public bool? SnUpdateCompletoBaseDatosBFA { get; set; } = false;
        public GetHashResponseDTO? HashDTO { get; set; } = null;
    }
}
