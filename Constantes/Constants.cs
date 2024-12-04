namespace BFASenado.Constantes
{
    public static class Constants
    {
        // Data
        public abstract class DataMessages
        {
            public const string NoRegistra = "No registra";
        }

        // DataAnnotations
        public abstract class DataAnnotationsErrorMessages
        {
            public const string Required = "El campo es obligatorio";
            public const string HashSHA256Length = "El hash debe tener exactamente 64 caracteres";
            public const string FormatoIncorrecto = "El formato es incorrecto";
            public const string GreaterThanZero = "El valor debe ser mayor a cero";
        }

        // Logs
        public abstract class LogMessages
        {
            // Error
            public const string GetBalanceError = "Error al obtener el balance/gas de la cuenta";
            public const string GetHashSHA256Error = "Error al obtener el hash SHA256";
            public const string GetPropiedadesArchivoError = "Error al obtener las propiedades de archivo";
            public const string GetHashNoExisteError = "El hash no existe";
            public const string GetHashError = "Error al obtener el hash";
            public const string GetHashesError = "Error al obtener los hashes";
            public const string HashDuplicadoError = "Intento de guardar un hash duplicado";
            public const string TransaccionGuardarError = "Error durante la transacción";
            public const string HashGuardarError = "Error al guardar el hash";
            public const string DBGuardarError = "Error al guardar en base de datos";
            public const string DBActualizarError = "Error al actualizar en base de datos";
            public const string NodoDisponibleError = "El nodo público de la BFA no está disponible";
            public const string NodoSincronizadoError = "El nodo público de la BFA no está sincronizado";
            public const string ServicioDisponibleError = "Servicio no disponible o no sincronizado";
            public const string HashGuardarMasivoError = "Error durante el guardado masivo de hashes";

            // Success
            public const string GetBalanceSuccess = "Balance/gas de la cuenta obtenido correctamente";
            public const string GetHashSHA256Success = "Hash SHA256 obtenido correctamente";
            public const string GetPropiedadesArchivoSuccess = "Propiedades de archivo obtenidas correctamente";
            public const string GetHashSuccess = "Hash obtenido correctamente";
            public const string GetHashesConFiltroSuccess = "Hashes obtenidos correctamente (con filtro)";
            public const string GetHashesSinFiltroSuccess = "Hashes obtenidos correctamente (sin filtro)";
            public const string TransaccionGuardarSuccess = "Transacción guardada en la BFA correctamente";
            public const string HashGuardarMasivoSuccess = "Guardado masivo de hashes realizado correctamente";
        }
    }
}
