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

namespace BackEnd
{
    public class Startup
    {
        private readonly IConfiguration _configuration;

        public Startup(IConfiguration configuration)
        {
            _configuration = configuration;
            Console.WriteLine("Startup constructor initialized");
            Console.WriteLine($"Configuration keys: {string.Join(", ", _configuration.AsEnumerable().Select(x => x.Key))}");
        }

        public void ConfigureServices(IServiceCollection services)
        {
            var stopwatch = Stopwatch.StartNew();
            Console.WriteLine("Starting ConfigureServices...");

            try
            {
                // Stage 1: Basic Services
                Console.WriteLine("Configuring basic services...");
                services.AddControllers();
                ConfigureSwagger(services);
                ConfigureCors(services);
                ConfigureFileUploadLimits(services);

                // Stage 2: Azure Services
                Console.WriteLine("Configuring Azure services...");
                var (cosmosClient, blobServiceClient) = ConfigureAzureServices(services);
                services.AddSingleton(cosmosClient);
                services.AddSingleton(blobServiceClient);
                services.AddScoped<CosmosDbContext>();

                // Stage 3: Additional Services
                Console.WriteLine("Configuring additional services...");
                ConfigureTusDotNet(services);

                Console.WriteLine($"ConfigureServices completed successfully in {stopwatch.ElapsedMilliseconds}ms");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"FATAL ERROR in ConfigureServices after {stopwatch.ElapsedMilliseconds}ms: {ex}");
                throw new Exception("Startup configuration failed", ex);
            }
        }

        private (CosmosClient, BlobServiceClient) ConfigureAzureServices(IServiceCollection services)
        {
            Console.WriteLine("Initializing Azure services...");

            try
            {
                // Key Vault Configuration
                Console.WriteLine("Retrieving Key Vault URL...");
                var keyVaultUrl = _configuration["KeyVault:Url"];
                if (string.IsNullOrEmpty(keyVaultUrl))
                {
                    throw new ArgumentNullException("KeyVault:Url", "Key Vault URL is missing in configuration");
                }
                Console.WriteLine($"Using Key Vault: {keyVaultUrl}");

                // Initialize Key Vault Client
                Console.WriteLine("Creating Key Vault client...");
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
                Console.WriteLine("Retrieving secrets from Key Vault...");
                var cosmosDbConnectionString = GetSecretWithRetry(secretClient, "CosmosDb", 3);
                var blobConnectionString = GetSecretWithRetry(secretClient, "BlobStorage", 3);
                var serviceBusConnectionString = GetSecretWithRetry(secretClient, "ServiceBusConnectionString", 2, optional: true);

                // Initialize Cosmos Client
                Console.WriteLine("Initializing Cosmos DB client...");
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
                Console.WriteLine("Initializing Blob Storage client...");
                var blobServiceClient = new BlobServiceClient(blobConnectionString);

                // Initialize Service Bus if available
                if (!string.IsNullOrEmpty(serviceBusConnectionString))
                {
                    Console.WriteLine("Initializing Service Bus client...");
                    services.AddSingleton(new ServiceBusClient(serviceBusConnectionString));
                }

                return (cosmosClient, blobServiceClient);
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Failed to configure Azure services: {ex}");
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
                    Console.WriteLine($"Attempt {retryCount + 1} to get secret {secretName}");
                    var secret = client.GetSecret(secretName);

                    if (string.IsNullOrEmpty(secret.Value.Value))
                    {
                        throw new Exception($"Secret {secretName} exists but is empty");
                    }

                    Console.WriteLine($"Successfully retrieved secret {secretName}");
                    return secret.Value.Value;
                }
                catch (Exception ex)
                {
                    retryCount++;
                    Console.WriteLine($"Failed to get secret {secretName} (attempt {retryCount}/{maxRetries}): {ex}");

                    if (retryCount >= maxRetries)
                    {
                        if (optional)
                        {
                            Console.WriteLine($"Secret {secretName} is optional and not available");
                            return string.Empty;
                        }
                        Console.WriteLine($"Failed to get required secret {secretName} after {maxRetries} attempts");
                        throw;
                    }

                    Thread.Sleep(1000 * retryCount); // Exponential backoff
                }
            }
        }

        private void ConfigureSwagger(IServiceCollection services)
        {
            Console.WriteLine("Configuring Swagger...");
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
            Console.WriteLine("Configuring CORS...");
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
            Console.WriteLine("Configuring file upload limits...");
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
            Console.WriteLine("Configuring TusDotNet...");
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
                            Console.WriteLine($"File upload completed: {ctx.FileId}");
                        }
                    }
                };
            });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            var stopwatch = Stopwatch.StartNew();
            Console.WriteLine("Starting Configure...");

            try
            {
                // Exception Handling
                if (env.IsDevelopment())
                {
                    Console.WriteLine("Enabling developer exception page");
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
                    Console.WriteLine($"Incoming request: {context.Request.Method} {context.Request.Path}");

                    var sw = Stopwatch.StartNew();
                    await next();
                    sw.Stop();

                    Console.WriteLine($"Request completed: {context.Response.StatusCode} in {sw.ElapsedMilliseconds}ms");
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
                        Console.WriteLine("Health check requested");
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

                Console.WriteLine($"Configure completed successfully in {stopwatch.ElapsedMilliseconds}ms");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"FATAL ERROR in Configure after {stopwatch.ElapsedMilliseconds}ms: {ex}");
                throw;
            }
        }
    }
}