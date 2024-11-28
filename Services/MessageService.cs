namespace BFASenado.Services
{
    public class MessageService : IMessageService
    {
        #region Attributes
        #endregion

        #region Constructor
        #endregion

        #region Methods

        // Success
        public string GetSha256HashSuccess()
        {
            return "Hash SHA256 obtenido correctamente";
        }

        public string GetBalanceSuccess()
        {
            return "Balance/gas de la cuenta obtenido correctamente";
        }

        public string GetHashSuccess()
        {
            return "Hash obtenido correctamente";
        }

        public string GetHashesSuccess()
        {
            return "Hashes obtenidos correctamente";
        }

        public string PostHashSuccess()
        {
            return "Hash guardado correctamente";
        }

        public string PostBaseDatosSuccess()
        {
            return "Registro guardado en Base de Datos correctamente";
        }



        // Error
        public string GetSha256HashError()
        {
            return "Error al obtener el hash SHA256 y Base64 del archivo";
        }

        public string GetBalanceError()
        {
            return "Error al obtener el balance/gas de la cuenta";
        }

        public string GetHashErrorFormatoIncorrecto()
        {
            return "El hash tiene un formato incorrecto";
        }

        public string GetHashErrorNotFound()
        {
            return "El hash no existe";
        }

        public string GetHashError()
        {
            return "Error al obtener el hash";
        }

        public string GetHashExists()
        {
            return "El hash ya existe";
        }

        public string PostHashError()
        {
            return "Error al guardar el hash";
        }

        public string GetHashesError()
        {
            return "Error al obtener los hashes";
        }

        public string GetBaseDatosError()
        {
            return "Error al consultar en Base de Datos";
        }

        public string PostBaseDatosError()
        {
            return "Error al guardar en Base de Datos";
        }

        public string PostBFAError()
        {
            return "Error al guardar en la BFA";
        }

        public string GetSincronizacionBFAError()
        {
            return "Error de sincronización del nodo de la BFA";
        }

        public string GetDisponibilidadBFAError()
        {
            return "El nodo de la BFA no está disponible";
        }

        public string GetBase64InputErrorFormatoIncorrecto()
        {
            return "El base64 tiene un formato incorrecto";
        }

        #endregion
    }
}
