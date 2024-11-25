using Nethereum.ABI.FunctionEncoding.Attributes;
using System.Numerics;

namespace BFASenado.DTO.HashDTO
{
    [FunctionOutput]
    public class HashDataDTO
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
    }
}
