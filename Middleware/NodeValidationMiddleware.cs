using BFASenado.Services.BFA;

namespace BFASenado.Middleware
{
    public class NodeValidationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IBFAService _BFAService;
       
        public NodeValidationMiddleware(RequestDelegate next, IBFAService BFAService)
        {
            _next = next;
            _BFAService = BFAService;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (!await _BFAService.IsNodeAvailable() || !await _BFAService.IsNodeSynced())
            {
                context.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                await context.Response.WriteAsync(Constantes.Constants.LogMessages.ServicioDisponibleError);
                return;
            }

            await _next(context);
        }
    }
}
