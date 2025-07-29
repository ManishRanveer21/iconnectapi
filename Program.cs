using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace BackEnd
{
    public class Program
    {
        public static void Main(string[] args)
        {
            CreateHostBuilder(args).Build().Run();
        }

        public static IHostBuilder CreateHostBuilder(string[] args) =>
            Host.CreateDefaultBuilder(args)
                .ConfigureWebHostDefaults(webBuilder =>
                {
                    webBuilder.CaptureStartupErrors(true); // Critical for Azure
                    webBuilder.UseStartup<Startup>();

                    // Remove UseUrls - Azure will handle the port binding
                    // webBuilder.UseUrls("http://0.0.0.0:8080"); 

                    // Add this for better error visibility
                    webBuilder.ConfigureLogging(logging =>
                    {
                        logging.AddConsole();
                        logging.AddDebug();
                    });
                });
    }
}