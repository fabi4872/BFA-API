namespace BFASenado.Services
{
    public interface IMessageService
    {
        // Success
        string GetBalanceSuccess();
        string GetHashSuccess();
        string GetHashesSuccess();
        string PostHashSuccess();



        // Error
        string GetBalanceError();
        string GetHashErrorFormatoIncorrecto();
        string GetHashErrorNotFound();
        string GetHashError();
        string GetHashExists();
        string PostHashError();
        string GetHashesError();
        string GetBaseDatosError();
        string PostBaseDatosError();
    }
}
