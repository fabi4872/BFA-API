using BFASenado.Models;
using BFASenado.Services;
using ElmahCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
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
            services.AddTransient<IMessageService, MessageService>();
            services.AddTransient<ILogService, LogService>();

            // Registrar IHttpContextAccessor
            services.AddHttpContextAccessor();

            // Configuración de ELMAH
            services.AddElmah();

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

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthorization();

            // Middleware de ELMAH
            app.UseElmah();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllers();
            });
        }
    }
}
