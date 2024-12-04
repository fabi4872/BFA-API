using Nethereum.ABI.FunctionEncoding.Attributes;
using System.Numerics;

namespace BFASenado.DTO.StampDTO
{
    [FunctionOutput]
    public class StampDTO
    {
        [Parameter("uint256[]", "objects", 1)]
        public List<BigInteger>? Objects { get; set; }

        [Parameter("address[]", "stampers", 2)]
        public List<string>? Stampers { get; set; }

        [Parameter("uint256[]", "blocknos", 3)]
        public List<BigInteger>? BlockNumbers { get; set; }

        [Parameter("uint256[]", "idTablas", 4)]
        public List<BigInteger>? IdTablas { get; set; }

        [Parameter("string[]", "nombreTablas", 5)]
        public List<string>? NombreTablas { get; set; }

        [Parameter("string[]", "detalles", 6)]
        public List<string>? Detalles { get; set; }

        [Parameter("string[]", "tipoDocumentos", 7)]
        public List<string>? TipoDocumentos { get; set; }
    }
}
