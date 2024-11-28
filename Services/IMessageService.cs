namespace BFASenado.Services
{
    public interface IMessageService
    {
        // Success
        string GetSha256HashSuccess();
        string GetBalanceSuccess();
        string GetHashSuccess();
        string GetHashesSuccess();
        string PostHashSuccess();
        string PostBaseDatosSuccess();



        // Error
        string GetSha256HashError();
        string GetBalanceError();
        string GetHashErrorFormatoIncorrecto();
        string GetHashErrorNotFound();
        string GetHashError();
        string GetHashExists();
        string PostHashError();
        string GetHashesError();
        string GetBaseDatosError();
        string PostBaseDatosError();
        string PostBFAError();
        string GetSincronizacionBFAError();
        string GetDisponibilidadBFAError();
        string GetBase64InputErrorFormatoIncorrecto();
    }
}
