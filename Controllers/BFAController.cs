using Microsoft.AspNetCore.Mvc;
using Nethereum.Web3.Accounts;
using System.Numerics;
using Nethereum.Web3;
using Nethereum.Hex.HexConvertors.Extensions;
using BFASenado.Models;
using Microsoft.EntityFrameworkCore;
using BFASenado.DTO.HashDTO;
using BFASenado.Services;
using System.Security.Cryptography;
using BFASenado.DTO.FileDTO;

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

        [HttpPost("ArchivoData")]
        public async Task<ActionResult<FileDTO?>> ArchivoData(IFormFile pdfFile)
        {
            if (pdfFile != null && pdfFile.Length > 0)
            {
                try
                {
                    using (var memoryStream = new MemoryStream())
                    {
                        // Leer el archivo de manera asíncrona
                        await pdfFile.CopyToAsync(memoryStream);
                        var pdfBytes = memoryStream.ToArray();

                        // Calcular el hash de manera síncrona (SHA256 no es asíncrono)
                        using (var sha256 = SHA256.Create())
                        {
                            byte[] hashBytes = sha256.ComputeHash(pdfBytes);
                            string hash = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();

                            // Calcular Base64
                            string base64 = Convert.ToBase64String(pdfBytes);

                            // Log Éxito
                            var log = _logService.CrearLog(
                                HttpContext,
                                null,
                                $"{_messageService.GetSha256HashSuccess()}",
                                null);
                            _logger.LogInformation("{@Log}", log);

                            // Retornar
                            return Ok(new FileDTO()
                            {
                                HashSHA256 = hash,
                                Base64 = base64
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    // Log Error
                    var log = _logService.CrearLog(
                        HttpContext,
                        null,
                        $"{_messageService.GetSha256HashError()}. {ex.Message}",
                        ex.StackTrace);
                    _logger.LogError("{@Log}", log);

                    throw new Exception($"{_messageService.GetSha256HashError()}. {ex.Message}. {ex.StackTrace}");
                }
            }

            return BadRequest(_messageService.GetSha256HashError());
        }

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
        public async Task<ActionResult<HashDTO?>> GuardarHash([FromBody] GuardarHashDTO input)
        {
            try
            {
                if (input == null || string.IsNullOrEmpty(input.Hash.Trim()) || string.IsNullOrEmpty(input.Base64.Trim()))
                {
                    // Log de formato incorrecto
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

                // Verificar existencia en DB y BFA
                var existsDB = await this.ObtenerTransaccionEnDB(hashHex);
                bool existsBFA = await checkHashFunction.CallAsync<bool>(hashHex);
                if (existsBFA || existsDB != null)
                {
                    // Log de hash existente
                    var logHashExists = _logService.CrearLog(
                        HttpContext,
                        input.Hash,
                        $"{_messageService.GetHashExists()}",
                        null);
                    _logger.LogInformation("{@Log}", logHashExists);

                    return BadRequest(_messageService.GetHashExists());
                }

                // Iniciar transacción en la base de datos
                using (var transaction = await _context.Database.BeginTransactionAsync())
                {
                    try
                    {
                        // Guardar en la base de datos
                        bool exitoDB = await this.GuardarTransaccionEnDB(input.Base64, hashHex);
                        if (!exitoDB)
                        {
                            throw new Exception($"{_messageService.PostBaseDatosError()}");
                        }

                        // Recuperar de base de datos
                        existsDB = await this.ObtenerTransaccionEnDB(hashHex);

                        // Guardar en la BFA
                        var objectList = new List<BigInteger> { hashValue };
                        var transactionHash = await putFunction.SendTransactionAsync(
                            account.Address,
                            new Nethereum.Hex.HexTypes.HexBigInteger(300000),
                            null,
                            objectList,
                            existsDB?.Id ?? 0,
                            Tabla
                        );

                        if (string.IsNullOrEmpty(transactionHash))
                        {
                            throw new Exception($"{_messageService.PostBFAError()}");
                        }

                        // Confirmar la transacción de la base de datos
                        await transaction.CommitAsync();

                        // Log Éxito
                        var log = _logService.CrearLog(
                            HttpContext,
                            input.Hash,
                            $"{_messageService.PostHashSuccess()}",
                            null);
                        _logger.LogInformation("{@Log}", log);

                        // Retornar el DTO del hash
                        return Ok(await this.GetHashDTO(hashHex, true));
                    }
                    catch (Exception ex)
                    {
                        // Revertir la transacción
                        await transaction.RollbackAsync();

                        // Log de error
                        var logError = _logService.CrearLog(
                            HttpContext,
                            input.Hash,
                            $"{_messageService.PostHashError()}. {ex.Message}",
                            ex.StackTrace);
                        _logger.LogError("{@Log}", logError);

                        throw new Exception($"{_messageService.PostHashError()}. {ex.Message}. {ex.StackTrace}");
                    }
                }
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

                throw new Exception($"{_messageService.PostHashError()}. {ex.Message}. {ex.StackTrace}");
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

                // Log Éxito
                var log = _logService.CrearLog(
                    HttpContext,
                    hash,
                    $"{_messageService.PostBaseDatosSuccess()}",
                    null);
                _logger.LogInformation("{@Log}", log);

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
