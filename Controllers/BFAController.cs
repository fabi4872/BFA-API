using Microsoft.AspNetCore.Mvc;
using Nethereum.Web3.Accounts;
using System.Numerics;
using Nethereum.Web3;
using Nethereum.Hex.HexConvertors.Extensions;
using BFASenado.Models;
using BFASenado.DTO.RequestDTO;
using BFASenado.Services;
using BFASenado.Services.Repository;
using BFASenado.DTO.ResponseDTO;
using BFASenado.Services.BFA;
using BFASenado.DTO.LogDTO;
using Nethereum.Contracts;

namespace BFASenado.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class BFAController : ControllerBase
    {
        #region Attributes

        // DB
        private readonly BFAContext _context;

        // BFAService
        private readonly IBFAService _BFAService;

        // Logger
        private readonly ILogger<BFAController> _logger;
        private readonly ILogService _logService;

        // Configuration
        private readonly IConfiguration _configuration;

        // TransaccionBFAService
        private readonly ITransaccionBFAService _transaccionBFAService;

        // Propiedades de appsettings
        private static string? UrlNodoPrueba;
        private static int ChainID;
        private static string? Sellador;
        private static string? PrivateKey;
        private static string? ContractAddress;
        private static string? ABI;

        #endregion

        #region Constructor

        public BFAController(
            IBFAService bfaService,
            ILogService logService,
            ILogger<BFAController> logger,
            BFAContext context,
            IConfiguration configuration,
            ITransaccionBFAService transaccionBFAService)
        {
            _BFAService = bfaService;
            _logService = logService;
            _logger = logger;
            _context = context;
            _configuration = configuration;
            _transaccionBFAService = transaccionBFAService;

            UrlNodoPrueba = _configuration.GetSection("UrlNodoPrueba").Value;
            ChainID = Convert.ToInt32(_configuration.GetSection("ChainID")?.Value);
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

                var logSuccess = _logService.CrearLog(
                    HttpContext,
                    Sellador,
                    Constantes.Constants.LogMessages.GetBalanceSuccess,
                    null);
                _logger.LogInformation("{@Log}", logSuccess);

                // Retornar el balance
                return Ok(balanceEther);
            }
            catch (Exception ex)
            {
                var logError = _logService.CrearLog(
                    HttpContext,
                    Sellador,
                    Constantes.Constants.LogMessages.GetBalanceError,
                    ex.Message);
                _logger.LogError("{@Log}", logError);

                throw new Exception($"{Constantes.Constants.LogMessages.GetBalanceError}. {ex.Message}");
            }
        }

        [HttpPost("ArchivoData")]
        public async Task<ActionResult<GetFileDTO?>> ArchivoData(IFormFile file)
        {
            if (file == null || file.Length == 0)
            {
                return BadRequest(Constantes.Constants.LogMessages.GetPropiedadesArchivoError);
            }

            try
            {
                using (var memoryStream = new MemoryStream())
                {
                    // Leer archivo
                    await file.CopyToAsync(memoryStream);
                    var fileBytes = memoryStream.ToArray();

                    // Calcular Hash
                    string hash = _BFAService.CalcularHashSHA256(fileBytes);

                    // Convertir a Base64
                    string base64 = Convert.ToBase64String(fileBytes);

                    var logSuccess = _logService.CrearLog(
                        HttpContext,
                        new { file?.FileName, file?.Length },
                        Constantes.Constants.LogMessages.GetPropiedadesArchivoSuccess,
                        null);
                    _logger.LogInformation("{@Log}", logSuccess);

                    // Retornar
                    return Ok(new GetFileDTO()
                    {
                        HashSHA256 = hash,
                        Base64 = base64
                    });
                }
            }
            catch (Exception ex)
            {
                var logError = _logService.CrearLog(
                    HttpContext,
                    new { file?.FileName, file?.Length },
                    Constantes.Constants.LogMessages.GetPropiedadesArchivoError,
                    ex.Message);
                _logger.LogError("{@Log}", logError);

                throw new Exception($"{Constantes.Constants.LogMessages.GetPropiedadesArchivoError}. {ex.Message}");
            }
        }

        [HttpPost("SHA256ByBase64")]
        public ActionResult<string> SHA256ByBase64([FromBody] Base64InputDTO base64Input)
        {
            try
            {
                // Convertir Base64 a arreglo de bytes
                byte[] fileBytes = Convert.FromBase64String(base64Input.Base64);

                // Calcular el hash SHA-256
                string hash = _BFAService.CalcularHashSHA256(fileBytes);

                var logSuccess = _logService.CrearLog(
                    HttpContext,
                    null,
                    Constantes.Constants.LogMessages.GetHashSHA256Success,
                    null);
                _logger.LogInformation("{@Log}", logSuccess);

                return Ok(hash);
            }
            catch (Exception ex)
            {
                var logError = _logService.CrearLog(
                    HttpContext,
                    null,
                    Constantes.Constants.LogMessages.GetHashSHA256Error,
                    ex.Message);
                _logger.LogError("{@Log}", logError);

                throw new Exception($"{Constantes.Constants.LogMessages.GetHashSHA256Error}. {ex.Message}");
            }
        }

        [HttpPost("HashBaseDatos")]
        public async Task<ActionResult<TransaccionBFA?>> HashBaseDatos([FromBody] GetHashSHA256DTO input)
        {
            try
            {
                TransaccionBFA? transaccion = await _transaccionBFAService.GetByHash(input.HashSHA256);

                if (transaccion != null)
                {
                    var logSuccess = _logService.CrearLog(
                        HttpContext,
                        input.HashSHA256,
                        Constantes.Constants.LogMessages.GetHashSuccess,
                        null);
                    _logger.LogInformation("{@Log}", logSuccess);

                    return Ok(transaccion);
                }

                var logWarning = _logService.CrearLog(
                        HttpContext,
                        input.HashSHA256,
                        Constantes.Constants.LogMessages.GetHashNoExisteError,
                        null
                    );
                _logger.LogWarning("{@Log}", logWarning);

                return BadRequest(Constantes.Constants.LogMessages.GetHashNoExisteError);
            }
            catch (Exception ex)
            {
                var logError = _logService.CrearLog(
                    HttpContext,
                    input.HashSHA256,
                    Constantes.Constants.LogMessages.GetHashError,
                    ex.Message);
                _logger.LogError("{@Log}", logError);

                return StatusCode(500, $"{Constantes.Constants.LogMessages.GetHashError}. {ex.Message}");
            }
        }

        [HttpPost("HashBFA")]
        public async Task<ActionResult<GetHashDTO>> HashBFA([FromBody] GetHashSHA256DTO input)
        {
            try
            {
                var result = await _BFAService.GetHashDTO(input.HashSHA256);

                if (result == null)
                {
                    var logWarning = _logService.CrearLog(
                       HttpContext,
                       input.HashSHA256,
                       Constantes.Constants.LogMessages.GetHashNoExisteError,
                       null
                   );
                    _logger.LogWarning("{@Log}", logWarning);

                    return BadRequest(Constantes.Constants.LogMessages.GetHashNoExisteError);
                }

                var logSuccess = _logService.CrearLog(
                    HttpContext,
                    input.HashSHA256,
                    Constantes.Constants.LogMessages.GetHashSuccess,
                    null
                );
                _logger.LogInformation("{@Log}", logSuccess);

                return Ok(result);
            }
            catch (Exception ex)
            {
                var logError = _logService.CrearLog(
                    HttpContext,
                    input.HashSHA256,
                    Constantes.Constants.LogMessages.GetHashError,
                    ex.Message
                );
                _logger.LogError("{@Log}", logError);

                return StatusCode(500, $"{Constantes.Constants.LogMessages.GetHashError}. {ex.Message}");
            }
        }

        [HttpPost("Hashes")]
        public async Task<ActionResult<List<GetHashDTO>>> Hashes([FromBody] GetHashListDTO input)
        {
            List<BigInteger> hashesList;
            
            try
            {
                LogDTO logSuccess;
                var account = new Account(PrivateKey, ChainID);
                var web3 = new Web3(account, UrlNodoPrueba);
                List<GetHashDTO> hashes = new List<GetHashDTO>();

                // Activar transacciones de tipo legacy
                web3.TransactionManager.UseLegacyAsDefault = true;

                // Cargar el contrato en la dirección especificada
                var contract = web3.Eth.GetContract(ABI, ContractAddress);

                if (input.IdTabla.HasValue || !string.IsNullOrEmpty(input.NombreTabla) || !string.IsNullOrEmpty(input.TipoDocumento))
                {
                    // Llamar a la función "getFilteredHashes" con filtros
                    var getFilteredHashesFunction = contract.GetFunction("getFilteredHashes");
                    hashesList = await getFilteredHashesFunction.CallAsync<List<BigInteger>>(
                        input.IdTabla ?? 0,
                        input.NombreTabla ?? "",
                        input.TipoDocumento ?? ""
                    );

                    logSuccess = _logService.CrearLog(
                        HttpContext, 
                        new { input.IdTabla, input.NombreTabla, input.TipoDocumento }, 
                        Constantes.Constants.LogMessages.GetHashesConFiltroSuccess, 
                        null);
                }
                else
                {
                    // Sin filtros: Llamar a "getAllHashes"
                    var getAllHashesFunction = contract.GetFunction("getAllHashes");
                    hashesList = await getAllHashesFunction.CallAsync<List<BigInteger>>();

                    logSuccess = _logService.CrearLog(
                        HttpContext,
                        null,
                        Constantes.Constants.LogMessages.GetHashesSinFiltroSuccess,
                        null);
                }

                // Convertir cada BigInteger en una cadena hexadecimal
                var hashStrings = hashesList?
                    .Select(h => "0x" + h.ToString("X").ToLower())
                    .ToList();

                foreach (var h in hashStrings)
                {
                    var hashDTO = await _BFAService.GetHashDTO(h);
                    if (hashDTO != null && !hashes.Any(existingHash => existingHash.Hash == hashDTO.Hash))
                    {
                        hashes.Add(hashDTO);
                    }
                }

                _logger.LogInformation("{@Log}", logSuccess);

                return Ok(hashes);
            }
            catch (Exception ex)
            {
                var logError = _logService.CrearLog(
                    HttpContext, 
                    null, 
                    Constantes.Constants.LogMessages.GetHashesError, 
                    ex.Message);
                
                _logger.LogError("{@Log}", logError);

                return StatusCode(500, $"{Constantes.Constants.LogMessages.GetHashesError}. {ex.Message}");
            }
        }

        [HttpPost("SaveHash")]
        public async Task<ActionResult<GetHashDTO?>> SaveHash([FromBody] GuardarHashDTO input)
        {
            try
            {
                var account = new Account(PrivateKey);
                var web3 = new Web3(account, UrlNodoPrueba);
                web3.TransactionManager.UseLegacyAsDefault = true;
                var contract = web3.Eth.GetContract(ABI, ContractAddress);
                var putFunction = contract.GetFunction("put");
                var result = await _BFAService.GetHashDTO(input.HashSHA256);
                BigInteger hashValue = input.HashSHA256.HexToBigInteger(false);
                string hashHex = input.HashSHA256;

                if (!hashHex.StartsWith("0x"))
                    hashHex = "0x" + hashHex;
                hashHex = hashHex.ToLower();

                // Verificar si el hash ya existe en la DB o en la BFA
                var transaccionDB = await _transaccionBFAService.GetByHash(input.HashSHA256);

                if (result != null || transaccionDB != null)
                {
                    var logWarning = _logService.CrearLog(
                        HttpContext,
                        input.HashSHA256,
                        Constantes.Constants.LogMessages.HashDuplicadoError,
                        null
                    );
                    _logger.LogWarning("{@Log}", logWarning);

                    return BadRequest(Constantes.Constants.LogMessages.HashDuplicadoError);
                }

                using (var transaction = await _context.Database.BeginTransactionAsync())
                {
                    try
                    {
                        // Guardar en la base de datos
                        await _transaccionBFAService.Save(new TransaccionBFA
                        {
                            Base64 = input.Base64,
                            Detalles = input.Detalles,
                            FechaAltaBFA = null,
                            FechaAltaTabla = DateTime.Now,
                            HashSHA256 = input.HashSHA256,
                            HashHexa = hashHex,
                            IdTabla = input.IdTabla,
                            NombreTabla = input.NombreTabla,
                            SnAltaBFA = false,
                            TipoDocumento = input.TipoDocumento
                        });

                        // Guardar en la BFA
                        var objectList = new List<BigInteger> { hashValue };
                        var transactionHash = await putFunction.SendTransactionAsync(
                            account.Address,
                            new Nethereum.Hex.HexTypes.HexBigInteger(300000),
                            null,
                            objectList,
                            input.IdTabla,
                            input.NombreTabla ?? Constantes.Constants.DataMessages.NoRegistra,
                            input.Detalles ?? Constantes.Constants.DataMessages.NoRegistra,
                            input.TipoDocumento ?? Constantes.Constants.DataMessages.NoRegistra
                        );

                        if (string.IsNullOrEmpty(transactionHash))
                        {
                            throw new Exception(Constantes.Constants.LogMessages.HashGuardarError);
                        }

                        await transaction.CommitAsync();

                        var logSuccess = _logService.CrearLog(
                            HttpContext,
                            input.HashSHA256,
                            Constantes.Constants.LogMessages.TransaccionGuardarSuccess,
                            null
                        );
                        _logger.LogInformation("{@Log}", logSuccess);

                        // Actualizar registro en base de datos
                        var resultRecuperado = await _BFAService.GetHashDTO(input.HashSHA256);
                        TransaccionBFA? recuperado = await _transaccionBFAService.GetByHash(input.HashSHA256);
                        if (resultRecuperado != null && recuperado != null)
                        {
                            recuperado.FechaAltaBFA = resultRecuperado.FechaAlta;
                            recuperado.SnAltaBFA = true;
                            await _transaccionBFAService.Update(recuperado);
                        }

                        // Retornar
                        return Ok(resultRecuperado);
                    }
                    catch (Exception ex)
                    {
                        await transaction.RollbackAsync();

                        var logError = _logService.CrearLog(
                            HttpContext,
                            input.HashSHA256,
                            Constantes.Constants.LogMessages.TransaccionGuardarError,
                            ex.Message
                        );
                        _logger.LogError("{@Log}", logError);

                        throw new Exception($"{Constantes.Constants.LogMessages.TransaccionGuardarError}. {ex.Message}");
                    }
                }
            }
            catch (Exception ex)
            {
                var logError = _logService.CrearLog(
                    HttpContext,
                    input.HashSHA256,
                    Constantes.Constants.LogMessages.HashGuardarError,
                    ex.Message
                );
                _logger.LogError("{@Log}", logError);

                return StatusCode(500, $"{Constantes.Constants.LogMessages.HashGuardarError}. {ex.Message}");
            }
        }

        [HttpGet("SaveMasivo")]
        public async Task<ActionResult<string>> SaveMasivo()
        {
            try
            {
                string resultString = await this.SaveHashMasivo();

                var logSuccess = _logService.CrearLog(
                    HttpContext,
                    null,
                    resultString,
                    null
                );
                _logger.LogError("{@Log}", logSuccess);

                return Ok(resultString);
            }
            catch (Exception ex)
            {
                var logError = _logService.CrearLog(
                    HttpContext,
                    null,
                    Constantes.Constants.LogMessages.HashGuardarMasivoError,
                    ex.Message
                );
                _logger.LogError("{@Log}", logError);

                return StatusCode(500, $"{Constantes.Constants.LogMessages.HashGuardarMasivoError}. {ex.Message}");
            }
        }



        // Métodos privados
        private async Task<string> SaveHashMasivo()
        {
            try
            {
                int cantidadImpactos = 0;
                var transacciones = await _transaccionBFAService.GetAll();
                var transaccionesPendientes = transacciones
                    .Where(x => x.FechaAltaBFA == null && x.SnAltaBFA == false)
                    .OrderBy(x => x.FechaAltaBFA ?? DateTime.MinValue);
                
                var account = new Account(PrivateKey);
                var web3 = new Web3(account, UrlNodoPrueba);
                web3.TransactionManager.UseLegacyAsDefault = true;

                var contract = web3.Eth.GetContract(ABI, ContractAddress);
                var putFunction = contract.GetFunction("put");

                foreach (var tr in transaccionesPendientes)
                {
                    if (await VerificarBFAYActualizarDB(tr))
                    {
                        cantidadImpactos++;
                        continue;
                    }

                    if (await GuardarEnBFA(tr, putFunction, account))
                    {
                        cantidadImpactos++;
                    }
                }

                return $"{Constantes.Constants.LogMessages.HashGuardarMasivoSuccess}. Cantidad de impactos: {cantidadImpactos}";
            }
            catch (Exception)
            {
                throw;
            }
        }

        private async Task<bool> VerificarBFAYActualizarDB(TransaccionBFA tr)
        {
            var encontrado = await _BFAService.GetHashDTO(tr.HashSHA256);

            if (encontrado != null)
            {
                tr.FechaAltaBFA = encontrado.FechaAlta;
                tr.SnAltaBFA = true;
                await _transaccionBFAService.Update(tr);
                return true;
            }

            return false;
        }

        private async Task<bool> GuardarEnBFA(TransaccionBFA tr, Function putFunction, Account account)
        {
            try
            {
                BigInteger hashValue = tr.HashSHA256.HexToBigInteger(false);
                var objectList = new List<BigInteger> { hashValue };
                var transactionHash = await putFunction.SendTransactionAsync(
                    account.Address,
                    new Nethereum.Hex.HexTypes.HexBigInteger(300000),
                    null,
                    objectList,
                    tr.IdTabla,
                    tr.NombreTabla ?? Constantes.Constants.DataMessages.NoRegistra,
                    tr.Detalles ?? Constantes.Constants.DataMessages.NoRegistra,
                    tr.TipoDocumento ?? Constantes.Constants.DataMessages.NoRegistra    
                );

                if (!string.IsNullOrEmpty(transactionHash))
                {
                    return await VerificarBFAYActualizarDB(tr);
                }

                _logger.LogError("{@Log}", _logService.CrearLog(
                    HttpContext,
                    tr.HashSHA256,
                    Constantes.Constants.LogMessages.HashGuardarError,
                    null
                ));
            }
            catch (Exception ex)
            {
                _logger.LogError("{@Log}", _logService.CrearLog(
                    HttpContext,
                    tr.HashSHA256,
                    Constantes.Constants.LogMessages.HashGuardarError,
                    ex.Message
                ));
            }

            return false;
        }

        #endregion
    }
}
