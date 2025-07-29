using Azure.Identity;
using Azure.Storage.Blobs;
using Microsoft.Azure.Cosmos;
using Microsoft.AspNetCore.Http.Features;
using tusdotnet;
using tusdotnet.Models;
using tusdotnet.Models.Configuration;
using tusdotnet.Stores;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using BackEnd.Entities;
using Microsoft.OpenApi.Models;
using Azure.Messaging.ServiceBus;
using Azure.Security.KeyVault.Secrets;

namespace BackEnd
{
    public class Startup
    {
        private readonly IConfiguration _configuration;

        public Startup(IConfiguration configuration)
        {
            _configuration = configuration;
            Console.WriteLine("Startup constructor called.");
        }

        public void ConfigureServices(IServiceCollection services)
        {
            try
            {
                Console.WriteLine("Starting ConfigureServices...");

                // Configure DefaultAzureCredential with specific options
                var credentialOptions = new DefaultAzureCredentialOptions
                {
                    ExcludeVisualStudioCredential = true,
                    ExcludeAzureCliCredential = false,
                    ExcludeEnvironmentCredential = true,
                    ExcludeManagedIdentityCredential = true,
                    ExcludeSharedTokenCacheCredential = true,
                    ExcludeInteractiveBrowserCredential = true,
                    TenantId = "f6d006d0-5280-44ab-9fa1-85c211e2ab03" // Your Directory ID
                };

                var keyVaultUrl = _configuration["KeyVault:Url"];
                if (string.IsNullOrEmpty(keyVaultUrl))
                {
                    throw new Exception("Key Vault URL is missing in configuration.");
                }

                // Build configuration with Key Vault
                var configurationBuilder = new ConfigurationBuilder()
                    .AddConfiguration(_configuration)
                    .AddAzureKeyVault(new Uri(keyVaultUrl), new DefaultAzureCredential(credentialOptions))
                    .Build();

                // Get secrets from Key Vault
                var cosmosDbConnectionString = configurationBuilder["CosmosDb"];
                var blobConnectionString = configurationBuilder["BlobStorage"];
                var serviceBusConnectionString = configurationBuilder["ServiceBusConnectionString"]; // Make sure this secret exists in your Key Vault

                // Validate required configurations
                if (string.IsNullOrEmpty(cosmosDbConnectionString) ||
                    string.IsNullOrEmpty(blobConnectionString))
                {
                    throw new Exception("Required connection strings are missing.");
                }

                // Configure Cosmos DB
                var cosmosClientOptions = new CosmosClientOptions
                {
                    ConnectionMode = ConnectionMode.Direct,
                    MaxRequestsPerTcpConnection = 10,
                    MaxTcpConnectionsPerEndpoint = 10
                };
                var cosmosClient = new CosmosClient(cosmosDbConnectionString, cosmosClientOptions);
                services.AddSingleton(cosmosClient);
                services.AddScoped<CosmosDbContext>();

                // Configure Blob Storage
                services.AddSingleton(new BlobServiceClient(blobConnectionString));

                // Configure Service Bus if connection string is available
                //if (!string.IsNullOrEmpty(serviceBusConnectionString))
                //{
                //    services.AddSingleton(new ServiceBusClient(serviceBusConnectionString));
                //    services.AddSingleton(provider =>
                //        provider.GetRequiredService<ServiceBusClient>().CreateSender(
                //            configurationBuilder.GetSection("ServiceBus")["QueueName"]));
                //}

                // Add configuration to DI
                services.AddSingleton<IConfiguration>(configurationBuilder);

                // Configure file upload limits
                services.Configure<FormOptions>(options =>
                {
                    options.MultipartBodyLengthLimit = 500 * 1024 * 1024;
                });

                services.Configure<IISServerOptions>(options =>
                {
                    options.MaxRequestBodySize = 500 * 1024 * 1024;
                });

                services.Configure<KestrelServerOptions>(options =>
                {
                    options.Limits.MaxRequestBodySize = 500 * 1024 * 1024;
                    options.Limits.RequestHeadersTimeout = TimeSpan.FromMinutes(10);
                    options.Limits.KeepAliveTimeout = TimeSpan.FromMinutes(10);
                });

                // Configure CORS
                services.AddCors(options =>
                {
                    options.AddPolicy("AllowSpecificOrigin", builder =>
                    {
                        builder.AllowAnyOrigin()
                               .AllowAnyHeader()
                               .AllowAnyMethod();
                    });
                });

                services.AddControllers();
                services.AddSwaggerGen(c =>
                {
                    c.SwaggerDoc("v1", new OpenApiInfo { Title = "My API", Version = "v1" });
                });

                Console.WriteLine("ConfigureServices completed successfully.");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error in ConfigureServices: {ex}");
                throw;
            }
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env, ILogger<Startup> logger)
        {
            try
            {
                logger.LogInformation("Starting Configure...");

                if (env.IsDevelopment())
                {
                    app.UseDeveloperExceptionPage();
                    app.UseSwagger();
                    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "My API V1"));
                }

                app.UseHttpsRedirection();
                app.UseRouting();
                app.UseCors("AllowSpecificOrigin");

                // Configure tusdotnet for file uploads
                app.UseTus(httpContext => new DefaultTusConfiguration
                {
                    Store = new TusDiskStore(Path.Combine(env.ContentRootPath, "uploads")),
                    UrlPath = "/files",
                    MaxAllowedUploadSizeInBytes = 500 * 1024 * 1024,
                    Events = new Events
                    {
                        OnFileCompleteAsync = async ctx =>
                        {
                            var fileId = ctx.FileId;
                            var filePath = Path.Combine(env.ContentRootPath, "uploads", fileId);
                            logger.LogInformation($"File {fileId} uploaded to {filePath}");
                        }
                    }
                });

                app.UseMiddleware<SkipAuthorizationMiddleware>();

                app.Use(async (context, next) =>
                {
                    logger.LogInformation("Request: {Method} {Path}", context.Request.Method, context.Request.Path);
                    await next.Invoke();
                    logger.LogInformation("Response: {StatusCode}", context.Response.StatusCode);
                });

                app.UseAuthorization();

                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapControllers();
                });

                logger.LogInformation("Application configured successfully.");
            }
            catch (Exception ex)
            {
                logger.LogError($"Configuration error: {ex}");
                throw;
            }
        }
    }
}