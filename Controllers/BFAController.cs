using Microsoft.AspNetCore.Mvc;
using Nethereum.Web3.Accounts;
using System.Numerics;
using Nethereum.Web3;
using Nethereum.Hex.HexConvertors.Extensions;
using BFASenado.Models;
using Microsoft.EntityFrameworkCore;
using BFASenado.DTO.HashDTO;
using BFASenado.Services;
using BFASenado.DTO.LogDTO;
using System.Security.Policy;

namespace BFASenado.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class BFAController : ControllerBase
    {
        #region Attributes

        // DB
        private readonly BFAContext _context;

        // Logger
        private readonly ILogger<BFAController> _logger;
        private readonly ILogService _logService;

        // Configuration
        private readonly IConfiguration _configuration;

        // MessageService
        private readonly IMessageService _messageService;

        // Propiedades de appsettings
        private static string? UrlNodoPrueba;
        private static int ChainID;
        private static string? Tabla;
        private static string? Sellador;
        private static string? PrivateKey;
        private static string? ContractAddress;
        private static string? ABI;

        #endregion

        #region Constructor

        public BFAController(
            ILogService logService,
            ILogger<BFAController> logger, 
            BFAContext context, 
            IConfiguration configuration,
            IMessageService messageService)
        {
            _logService = logService;
            _logger = logger;
            _context = context;
            _configuration = configuration;
            _messageService = messageService;

            UrlNodoPrueba = _configuration.GetSection("UrlNodoPrueba").Value;
            ChainID = Convert.ToInt32(_configuration.GetSection("ChainID")?.Value);
            Tabla = _configuration.GetSection("Tabla").Value;
            Sellador = _configuration.GetSection("Sellador").Value;
            PrivateKey = _configuration.GetSection("PrivateKey").Value;
            ContractAddress = _configuration.GetSection("ContractAddress").Value;
            ABI = _configuration.GetSection("ABI").Value;
        }

        #endregion

        #region Methods

        [HttpGet("Balance")]
        public async Task<ActionResult<decimal>> Balance()
        {
            try
            {
                var web3 = new Web3(UrlNodoPrueba);
                var balanceWei = await web3.Eth.GetBalance.SendRequestAsync(Sellador);
                var balanceEther = Web3.Convert.FromWei(balanceWei);

                // Log Éxito
                var log = _logService.CrearLog(
                    HttpContext, 
                    null, 
                    $"{_messageService.GetBalanceSuccess()}", 
                    null);
                _logger.LogInformation("{@Log}", log);

                // Retornar el balance
                return Ok(balanceEther);
            }
            catch (Exception ex)
            {
                // Log Error
                var log = _logService.CrearLog(
                    HttpContext, 
                    null, 
                    $"{_messageService.GetBalanceError()}. {ex.Message}", 
                    ex.StackTrace);
                _logger.LogError("{@Log}", log);
                
                throw new Exception($"{_messageService.GetBalanceError()}. {ex.Message}. {ex.StackTrace}");
            }
        }

        [HttpGet("Hash")]
        public async Task<ActionResult<HashDTO>> Hash([FromQuery] string hash)
        {
            try
            {
                if (string.IsNullOrEmpty(hash.Trim()))
                {
                    // Log
                    var logFormatoIncorrecto = _logService.CrearLog(
                        HttpContext,
                        hash,
                        $"{_messageService.GetHashErrorFormatoIncorrecto()}",
                        null);
                    _logger.LogInformation("{@Log}", logFormatoIncorrecto);

                    return BadRequest(_messageService.GetHashErrorFormatoIncorrecto());
                }

                HashDTO? responseData = await this.GetHashDTO(hash, true);

                if (responseData == null)
                {
                    // Log
                    var logNotFound = _logService.CrearLog(
                        HttpContext,
                        hash,
                        $"{_messageService.GetHashErrorNotFound()}",
                        null);
                    _logger.LogInformation("{@Log}", logNotFound);

                    return NotFound($"{_messageService.GetHashErrorNotFound()}: {hash}");
                }

                // Log Éxito
                var log = _logService.CrearLog(
                    HttpContext,
                    hash,
                    $"{_messageService.GetHashSuccess()}",
                    null);
                _logger.LogInformation("{@Log}", log);

                // Retornar el hash
                return Ok(responseData);
            }
            catch (Exception ex)
            {
                // Log Error
                var log = _logService.CrearLog(
                    HttpContext,
                    hash,
                    $"{_messageService.GetHashError()}. {ex.Message}",
                    ex.StackTrace);
                _logger.LogError("{@Log}", log);

                throw new Exception($"{_messageService.GetHashError()}. {ex.Message}. {ex.StackTrace}");
            }
        }

        [HttpGet("Hashes")]
        public async Task<ActionResult<List<HashDTO>>> GetHashes()
        {
            try
            {
                var account = new Account(PrivateKey, ChainID);
                var web3 = new Web3(account, UrlNodoPrueba);
                List<HashDTO> hashes = new List<HashDTO>();

                // Activar transacciones de tipo legacy
                web3.TransactionManager.UseLegacyAsDefault = true;

                // Cargar el contrato en la dirección especificada
                var contract = web3.Eth.GetContract(ABI, ContractAddress);

                // Llamar a la función "getAllHashes" del contrato
                var getAllHashesFunction = contract.GetFunction("getAllHashes");
                var hashesList = await getAllHashesFunction.CallAsync<List<BigInteger>>();

                // Convertir cada BigInteger en una cadena hexadecimal
                var hashStrings = hashesList?
                    .Select(h => "0x" + h.ToString("X").ToLower())
                    .ToList();

                // Insertar hashStrings en lista de hashes
                foreach (var h in hashStrings)
                {
                    var hashDTO = await this.GetHashDTO(h, false);
                    if (hashDTO != null)
                    {
                        hashes.Add(hashDTO);
                    }
                }

                // Log Éxito
                var log = _logService.CrearLog(
                    HttpContext,
                    null,
                    $"{_messageService.GetHashesSuccess()}",
                    null);
                _logger.LogInformation("{@Log}", log);

                // Retornar la lista de hashes
                return Ok(hashes);
            }
            catch (Exception ex)
            {
                // Log Error
                var log = _logService.CrearLog(
                    HttpContext,
                    null,
                    $"{_messageService.GetHashesError()}. {ex.Message}",
                    ex.StackTrace);
                _logger.LogError("{@Log}", log);

                throw new Exception($"{_messageService.GetHashesError()}. {ex.Message}. {ex.StackTrace}");
            }
        }

        [HttpPost("GuardarHash")]
        public async Task<ActionResult<HashDTO>> GuardarHash([FromBody] GuardarHashDTO input)
        {
            try
            {
                if (string.IsNullOrEmpty(input.Hash?.Trim()))
                {
                    // Log
                    var logFormatoIncorrecto = _logService.CrearLog(
                        HttpContext,
                        input.Hash,
                        $"{_messageService.GetHashErrorFormatoIncorrecto()}",
                        null);
                    _logger.LogInformation("{@Log}", logFormatoIncorrecto);

                    return BadRequest(_messageService.GetHashErrorFormatoIncorrecto());
                }

                var account = new Account(PrivateKey);
                var web3 = new Web3(account, UrlNodoPrueba);
                web3.TransactionManager.UseLegacyAsDefault = true;

                var contract = web3.Eth.GetContract(ABI, ContractAddress);
                var putFunction = contract.GetFunction("put");

                BigInteger hashValue = input.Hash.HexToBigInteger(false);
                string hashHex = "0x" + hashValue.ToString("X");

                var checkHashFunction = contract.GetFunction("checkHash");
                bool exists = await checkHashFunction.CallAsync<bool>(hashHex);
                if (exists)
                {
                    // Log
                    var logHashExists = _logService.CrearLog(
                        HttpContext,
                        input.Hash,
                        $"{_messageService.GetHashExists()}",
                        null);
                    _logger.LogInformation("{@Log}", logHashExists);

                    return BadRequest(_messageService.GetHashExists());
                }

                bool exito = await this.GuardarTransaccionEnDB(input.Base64, hashHex);
                if (exito)
                {
                    var transaccion = await this.ObtenerTransaccionEnDB(hashHex);

                    if (transaccion != null)
                    {
                        var objectList = new List<BigInteger> { hashValue };
                        var transactionHash = await putFunction.SendTransactionAsync(
                            account.Address,
                            new Nethereum.Hex.HexTypes.HexBigInteger(300000),
                            null,
                            objectList,
                            transaccion.Id,
                            Tabla
                        );
                    }
                }

                // Log Éxito
                var log = _logService.CrearLog(
                    HttpContext,
                    input.Hash,
                    $"{_messageService.PostHashSuccess()}",
                    null);
                _logger.LogInformation("{@Log}", log);

                // Retornar el hash guardado
                return Ok(await this.GetHashDTO(hashHex, false));
            }
            catch (Exception ex)
            {
                // Log Error
                var log = _logService.CrearLog(
                    HttpContext,
                    input.Hash,
                    $"{_messageService.PostHashError()}. {ex.Message}",
                    ex.StackTrace);
                _logger.LogError("{@Log}", log);

                throw new Exception($"{_messageService.PostHashError}. {ex.Message}. {ex.StackTrace}");
            }
        }



        // Métodos privados
        private async Task<HashDTO?> GetHashDTO(string hash, bool showBase64)
        {
            if (!hash.StartsWith("0x"))
                hash = "0x" + hash;
            hash = hash.ToLower();

            BigInteger hashValue = hash.HexToBigInteger(false);

            var account = new Account(PrivateKey, ChainID);
            var web3 = new Web3(account, UrlNodoPrueba);
            web3.TransactionManager.UseLegacyAsDefault = true;

            var contract = web3.Eth.GetContract(ABI, ContractAddress);
            var getHashDataFunction = contract.GetFunction("getHashData");
            var result = await getHashDataFunction.CallDeserializingToObjectAsync<HashDataDTO>(hashValue);

            if (result.BlockNumbers == null || result.BlockNumbers.Count == 0)
            {
                return null;
            }

            BigInteger blockNumber = result.BlockNumbers[0];
            var block = await web3.Eth.Blocks.GetBlockWithTransactionsByNumber.SendRequestAsync(new Nethereum.Hex.HexTypes.HexBigInteger(blockNumber));

            DateTimeOffset timeStamp = DateTimeOffset.FromUnixTimeSeconds((long)block.Timestamp.Value);
            DateTime argentinaTime = timeStamp.ToOffset(TimeSpan.FromHours(-3)).DateTime;
            string formattedTimeStamp = argentinaTime.ToString("dd/MM/yyyy HH:mm:ss");

            var tr = await this.ObtenerTransaccionEnDB(hash);
            string hashRecuperado = result.Objects != null && result.Objects.Count > 0 ? "0x" + result.Objects[0].ToString("X") : "No registra";
            string signerAddress = result.Stampers != null && result.Stampers.Count > 0 ? result.Stampers[0] : "No registra";

            return new HashDTO
            {
                NumeroBloque = blockNumber.ToString(),
                FechaAlta = formattedTimeStamp,
                Hash = hashRecuperado,
                IdTabla = result.IdTablas != null && result.IdTablas.Any() ? result.IdTablas[0].ToString() : "No registra",
                NombreTabla = result.NombreTablas?.FirstOrDefault() ?? "No registra",
                Sellador = signerAddress,
                Base64 = showBase64 ? tr?.Base64 : null
            };
        }

        private async Task<bool> GuardarTransaccionEnDB(string base64, string hash)
        {
            try
            {
                Transaccion transaccion = new Transaccion()
                {
                    Base64 = base64,
                    Hash = hash
                };

                _context.Transaccions.Add(transaccion);
                await _context.SaveChangesAsync();
                return true;
            }
            catch (Exception ex)
            {
                // Log Error
                var log = _logService.CrearLog(
                    HttpContext,
                    hash,
                    $"{_messageService.PostBaseDatosError()}. {ex.Message}",
                    ex.StackTrace);
                _logger.LogError("{@Log}", log);

                throw new Exception($"{_messageService.PostBaseDatosError()}. {ex.Message}. {ex.StackTrace}");
            }
        }

        private async Task<Transaccion?> ObtenerTransaccionEnDB(string hash)
        {
            try
            {
                return await _context.Transaccions.FirstOrDefaultAsync(x => x.Hash == hash);
            }
            catch (Exception ex)
            {
                // Log Error
                var log = _logService.CrearLog(
                    HttpContext,
                    hash,
                    $"{_messageService.GetBaseDatosError()}. {ex.Message}",
                    ex.StackTrace);
                _logger.LogError("{@Log}", log);

                throw new Exception($"{_messageService.GetBaseDatosError()}. {ex.Message}. {ex.StackTrace}");
            }
        }

        #endregion
    }
}
