namespace BFASenado.DTO.ResponseDTO
{
    public class GetFileResponseDTO
    {
        public string HashSHA256 { get; set; } = null!;
        public string Base64 { get; set; } = null!;
    }
}
