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
using System.Diagnostics;
using Microsoft.Extensions.Logging;

namespace BackEnd
{
    public class Startup
    {
        private readonly IConfiguration _configuration;
        private readonly ILogger<Startup> _logger;

        public Startup(IConfiguration configuration, ILogger<Startup> logger)
        {
            _configuration = configuration;
            _logger = logger;

            _logger.LogInformation("Startup constructor initialized");
            _logger.LogDebug("Configuration keys: {ConfigurationKeys}",
                string.Join(", ", _configuration.AsEnumerable().Select(x => x.Key)));
        }

        public void ConfigureServices(IServiceCollection services)
        {
            var stopwatch = Stopwatch.StartNew();
            _logger.LogInformation("Starting ConfigureServices...");

            try
            {
                // Stage 1: Basic Services
                _logger.LogInformation("Configuring basic services...");
                services.AddControllers();
                ConfigureSwagger(services);
                ConfigureCors(services);
                ConfigureFileUploadLimits(services);

                // Stage 2: Azure Services
                _logger.LogInformation("Configuring Azure services...");
                var (cosmosClient, blobServiceClient) = ConfigureAzureServices(services);
                services.AddSingleton(cosmosClient);
                services.AddSingleton(blobServiceClient);
                services.AddScoped<CosmosDbContext>();

                // Stage 3: Additional Services
                _logger.LogInformation("Configuring additional services...");
                ConfigureTusDotNet(services);

                _logger.LogInformation("ConfigureServices completed successfully in {ElapsedMilliseconds}ms",
                    stopwatch.ElapsedMilliseconds);
            }
            catch (Exception ex)
            {
                _logger.LogCritical(ex, "FATAL ERROR in ConfigureServices after {ElapsedMilliseconds}ms",
                    stopwatch.ElapsedMilliseconds);
                throw new Exception("Startup configuration failed", ex);
            }
        }

        private (CosmosClient, BlobServiceClient) ConfigureAzureServices(IServiceCollection services)
        {
            _logger.LogInformation("Initializing Azure services...");

            try
            {
                // Key Vault Configuration
                _logger.LogInformation("Retrieving Key Vault URL...");
                var keyVaultUrl = _configuration["KeyVault:Url"];
                if (string.IsNullOrEmpty(keyVaultUrl))
                {
                    throw new ArgumentNullException("KeyVault:Url", "Key Vault URL is missing in configuration");
                }
                _logger.LogInformation("Using Key Vault: {KeyVaultUrl}", keyVaultUrl);

                // Initialize Key Vault Client
                _logger.LogInformation("Creating Key Vault client...");
                var credential = new DefaultAzureCredential(new DefaultAzureCredentialOptions
                {
                    ExcludeVisualStudioCredential = true,
                    ExcludeAzureCliCredential = false,
                    ExcludeEnvironmentCredential = false,
                    ExcludeManagedIdentityCredential = false,
                    ExcludeSharedTokenCacheCredential = true,
                    ExcludeInteractiveBrowserCredential = true,
                    TenantId = "f6d006d0-5280-44ab-9fa1-85c211e2ab03"
                });

                var secretClient = new SecretClient(new Uri(keyVaultUrl), credential);
                services.AddSingleton(secretClient);

                // Get Secrets with Retry Policy
                _logger.LogInformation("Retrieving secrets from Key Vault...");
                var cosmosDbConnectionString = GetSecretWithRetry(secretClient, "CosmosDb", 3);
                var blobConnectionString = GetSecretWithRetry(secretClient, "BlobStorage", 3);
                var serviceBusConnectionString = GetSecretWithRetry(secretClient, "ServiceBusConnectionString", 2, optional: true);

                // Initialize Cosmos Client
                _logger.LogInformation("Initializing Cosmos DB client...");
                var cosmosClient = new CosmosClient(cosmosDbConnectionString, new CosmosClientOptions
                {
                    ConnectionMode = ConnectionMode.Direct,
                    MaxRequestsPerTcpConnection = 10,
                    MaxTcpConnectionsPerEndpoint = 10,
                    SerializerOptions = new CosmosSerializationOptions
                    {
                        PropertyNamingPolicy = CosmosPropertyNamingPolicy.CamelCase
                    }
                });

                // Initialize Blob Client
                _logger.LogInformation("Initializing Blob Storage client...");
                var blobServiceClient = new BlobServiceClient(blobConnectionString);

                // Initialize Service Bus if available
                if (!string.IsNullOrEmpty(serviceBusConnectionString))
                {
                    _logger.LogInformation("Initializing Service Bus client...");
                    services.AddSingleton(new ServiceBusClient(serviceBusConnectionString));
                }

                return (cosmosClient, blobServiceClient);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to configure Azure services");
                throw;
            }
        }

        private string GetSecretWithRetry(SecretClient client, string secretName, int maxRetries, bool optional = false)
        {
            var retryCount = 0;
            while (true)
            {
                try
                {
                    _logger.LogDebug("Attempt {RetryCount} to get secret {SecretName}", retryCount + 1, secretName);
                    var secret = client.GetSecret(secretName);

                    if (string.IsNullOrEmpty(secret.Value.Value))
                    {
                        throw new Exception($"Secret {secretName} exists but is empty");
                    }

                    _logger.LogDebug("Successfully retrieved secret {SecretName}", secretName);
                    return secret.Value.Value;
                }
                catch (Exception ex)
                {
                    retryCount++;
                    _logger.LogWarning(ex, "Failed to get secret {SecretName} (attempt {RetryCount}/{MaxRetries})",
                        secretName, retryCount, maxRetries);

                    if (retryCount >= maxRetries)
                    {
                        if (optional)
                        {
                            _logger.LogWarning("Secret {SecretName} is optional and not available", secretName);
                            return string.Empty;
                        }
                        _logger.LogError(ex, "Failed to get required secret {SecretName} after {MaxRetries} attempts",
                            secretName, maxRetries);
                        throw;
                    }

                    Thread.Sleep(1000 * retryCount); // Exponential backoff
                }
            }
        }

        private void ConfigureSwagger(IServiceCollection services)
        {
            _logger.LogInformation("Configuring Swagger...");
            services.AddSwaggerGen(c =>
            {
                c.SwaggerDoc("v1", new OpenApiInfo { Title = "My API", Version = "v1" });
                c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
                {
                    Description = "JWT Authorization header",
                    Name = "Authorization",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = "Bearer"
                });
            });
        }

        private void ConfigureCors(IServiceCollection services)
        {
            _logger.LogInformation("Configuring CORS...");
            services.AddCors(options =>
            {
                options.AddPolicy("AllowSpecificOrigin", builder =>
                {
                    builder.AllowAnyOrigin()
                           .AllowAnyHeader()
                           .AllowAnyMethod();
                });
            });
        }

        private void ConfigureFileUploadLimits(IServiceCollection services)
        {
            _logger.LogInformation("Configuring file upload limits...");
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
        }

        private void ConfigureTusDotNet(IServiceCollection services)
        {
            _logger.LogInformation("Configuring TusDotNet...");
            services.AddSingleton(provider =>
            {
                var env = provider.GetRequiredService<IWebHostEnvironment>();
                return new DefaultTusConfiguration
                {
                    Store = new TusDiskStore(Path.Combine(env.ContentRootPath, "uploads")),
                    UrlPath = "/files",
                    MaxAllowedUploadSizeInBytes = 500 * 1024 * 1024,
                    Events = new Events
                    {
                        OnFileCompleteAsync = async ctx =>
                        {
                            var logger = provider.GetRequiredService<ILogger<Startup>>();
                            logger.LogInformation("File upload completed: {FileId}", ctx.FileId);
                        }
                    }
                };
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            var stopwatch = Stopwatch.StartNew();
            _logger.LogInformation("Starting Configure...");

            try
            {
                // Exception Handling
                if (env.IsDevelopment())
                {
                    _logger.LogInformation("Enabling developer exception page");
                    app.UseDeveloperExceptionPage();
                    app.UseSwagger();
                    app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "My API V1"));
                }
                else
                {
                    app.UseExceptionHandler("/error");
                    app.UseHsts();
                }

                // Middleware Pipeline
                app.UseHttpsRedirection();
                app.UseRouting();
                app.UseCors("AllowSpecificOrigin");

                // Request Logging
                app.Use(async (context, next) =>
                {
                    var logger = context.RequestServices.GetRequiredService<ILogger<Startup>>();
                    logger.LogInformation("Incoming request: {Method} {Path}", context.Request.Method, context.Request.Path);

                    var stopwatch = Stopwatch.StartNew();
                    await next();
                    stopwatch.Stop();

                    logger.LogInformation("Request completed: {StatusCode} in {ElapsedMilliseconds}ms",
                        context.Response.StatusCode, stopwatch.ElapsedMilliseconds);
                });

                // TusDotNet File Uploads
                app.UseTus(context => context.RequestServices.GetRequiredService<DefaultTusConfiguration>());

                app.UseMiddleware<SkipAuthorizationMiddleware>();
                app.UseAuthorization();

                // Endpoints
                app.UseEndpoints(endpoints =>
                {
                    endpoints.MapControllers();

                    // Health check endpoint
                    endpoints.MapGet("/health", async context =>
                    {
                        var logger = context.RequestServices.GetRequiredService<ILogger<Startup>>();
                        logger.LogInformation("Health check requested");
                        await context.Response.WriteAsync("Healthy");
                    });

                    // Configuration dump endpoint (for debugging)
                    if (env.IsDevelopment())
                    {
                        endpoints.MapGet("/config", async context =>
                        {
                            var config = context.RequestServices.GetRequiredService<IConfiguration>();
                            await context.Response.WriteAsJsonAsync(config.AsEnumerable());
                        });
                    }
                });

                _logger.LogInformation("Configure completed successfully in {ElapsedMilliseconds}ms",
                    stopwatch.ElapsedMilliseconds);
            }
            catch (Exception ex)
            {
                _logger.LogCritical(ex, "FATAL ERROR in Configure after {ElapsedMilliseconds}ms",
                    stopwatch.ElapsedMilliseconds);
                throw;
            }
        }
    }
}