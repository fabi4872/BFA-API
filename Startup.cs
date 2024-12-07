using BFASenado.Middleware;
using BFASenado.Models;
using BFASenado.Services;
using BFASenado.Services.BFA;
using BFASenado.Services.Repository;
using ElmahCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using System.Text.Json.Serialization;

namespace BFASenado
{
    public class Startup
    {
        public IConfiguration Configuration { get; }

        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();

            string currentDate = DateTime.Now.Date.ToString("dd-MM-yyyy");
            var logPath = Path.Combine(Directory.GetCurrentDirectory(), $"LogsELMAH/{currentDate}");
           
            services.AddElmah(options =>
            {
                options.Path = "/elmah"; // Ruta para acceder a Elmah
                options.LogPath = logPath; // Usar la ruta absoluta configurada arriba
                options.ApplicationName = "BFASenado";
            });

            services.AddControllers().AddJsonOptions(x => x.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles).AddNewtonsoftJson();

            var connection = Configuration.GetConnectionString("DefaultConnection");
            services.AddDbContext<BFAContext>(options => options.UseSqlServer(connection));

            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            services.AddEndpointsApiExplorer();

            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "BFASenado", Version = "v1" });
            });

            services.AddAutoMapper(typeof(Startup));
            services.AddTransient<ITransaccionBFAService, TransaccionBFAService>();
            services.AddTransient<ILogService, LogService>();
            services.AddTransient<IBFAService, BFAService>();

            // Registrar IHttpContextAccessor
            services.AddHttpContextAccessor();

            services.AddLogging(builder =>
            {
                builder.AddFile("Logs/app-{Date}.log"); // Guarda logs en la carpeta Logs
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseSwagger();
                app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "BFASenado v1"));
            }

            app.UseMiddleware<NodeValidationMiddleware>();

            // Middleware para capturar errores HTTP
            app.Use(async (context, next) =>
            {
                // Interceptar el flujo de la respuesta
                var originalBodyStream = context.Response.Body;
                using var memoryStream = new MemoryStream();
                context.Response.Body = memoryStream;
                var dateTime = DateTime.UtcNow;

                try
                {
                    await next();

                    // Capturar errores HTTP 400-503
                    if (context.Response.StatusCode >= 400 && context.Response.StatusCode <= 503)
                    {
                        // Leer el cuerpo de la respuesta
                        memoryStream.Seek(0, SeekOrigin.Begin);
                        var responseBody = await new StreamReader(memoryStream).ReadToEndAsync();
                        memoryStream.Seek(0, SeekOrigin.Begin);

                        // Registrar en Elmah
                        var ex = new Exception($"HTTP Error: {context.Response.StatusCode}. Details: {responseBody}");
                        await this.GuardarArchivoELMAHLog(dateTime, ex, context, Constantes.Constants.DataMessages.NoRegistra, responseBody);
                    }
                }
                catch (Exception ex)
                {
                    // Manejar excepciones no controladas
                    context.Response.StatusCode = 500;

                    // Registrar en Elmah
                    await this.GuardarArchivoELMAHLog(dateTime, ex, context, $"{ex.Message}. {ex.StackTrace}");

                    throw;
                }
                finally
                {
                    // Restaurar el flujo original
                    memoryStream.Seek(0, SeekOrigin.Begin);
                    await memoryStream.CopyToAsync(originalBodyStream);
                    context.Response.Body = originalBodyStream;
                }
            });


            app.UseElmah();

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }



        // Métodos privados
        private async Task GuardarArchivoELMAHLog(
            DateTime dateTime,
            Exception ex,
            HttpContext? context = null, 
            string? excepcion = Constantes.Constants.DataMessages.NoRegistra, 
            string? responseBody = Constantes.Constants.DataMessages.NoRegistra)
        {
            try
            {
                string currentDate = DateTime.Now.Date.ToString("dd-MM-yyyy");
                var directoryPath = Path.Combine(Directory.GetCurrentDirectory(), $"LogsELMAH/{currentDate}");
                if (!Directory.Exists(directoryPath))
                {
                    Directory.CreateDirectory(directoryPath);
                }
                var logFilePath = Path.Combine(directoryPath, $"{DateTime.UtcNow:yyyyMMdd_HHmmssfff}_exception.log");

                string path = context?.Request?.Path ?? Constantes.Constants.DataMessages.NoRegistra;
                string method = context?.Request?.Method ?? Constantes.Constants.DataMessages.NoRegistra;
                int statusCode = context?.Response?.StatusCode ?? 0;

                var errorDetails = $@"
                Timestamp: {dateTime}
                Path: {path}
                Method: {method}
                Status Code: {statusCode}
                Exception: {excepcion}
                ResponseBody: {responseBody}
                ";

                // Registrar archivo
                await File.AppendAllTextAsync(logFilePath, errorDetails);

                // Registrar en Elmah
                ElmahCore.ElmahExtensions.RaiseError(context, ex);
            }
            catch (Exception)
            {
                throw;
            }
        }
    }
}
