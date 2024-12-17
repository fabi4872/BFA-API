namespace BFASenado.DTO.ResponseDTO
{
    public class GetHashesResponseDTO
    {
        public bool SnVerificaUltimoHashGuardado { get; set; } = false;
        public bool SnEsUltimoHashGuardado { get; set; } = false;
        public GetHashResponseDTO? UltimoHashGuardado { get; set; } = null;
        public List<GetHashResponseDTO>? Hashes { get; set; }
    }
}
