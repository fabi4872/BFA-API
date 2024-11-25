using Nethereum.ABI.FunctionEncoding.Attributes;
using Nethereum.Contracts;
using System.Numerics;

namespace BFASenado.Services
{
    public class StandardTokenDeployment : ContractDeploymentMessage
    {
        #region Attributes

        private readonly IConfiguration _configuration;
        
        #endregion

        #region Constructor

        public StandardTokenDeployment(IConfiguration configuration) : 
            base(configuration.GetSection("ByteCode").Value ?? throw new ArgumentNullException("ByteCode"))
        {
            _configuration = configuration;
        }

        #endregion

        #region Methods

        [Parameter("uint256", "totalSupply")]
        public BigInteger TotalSupply { get; set; }

        #endregion        
    }
}
