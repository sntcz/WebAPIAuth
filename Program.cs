using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Server.IISIntegration;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Net.Http.Headers;
using Microsoft.OpenApi.Models;
using WebAPIAuth.ApiKey;

namespace WebAPIAuth
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen(options =>
            {
                options.SwaggerDoc("v1", new OpenApiInfo
                {
                    Title = "WeatherForecastAPI",
                    Version = "v1",
                    Description = "Weather forecast test API with authorization.",
                });

                // Set the comments path for the Swagger JSON and UI.
                // Add <GenerateDocumentationFile>true</GenerateDocumentationFile> to project file
                var xmlFile = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
                var xmlPath = Path.Combine(AppContext.BaseDirectory, xmlFile);
                options.IncludeXmlComments(xmlPath);

                // The AddSecurityDefinition and AddSecurityRequirement methods enable the JWT and API KEY
                // authentication for the Swagger UI.
                OpenApiSecurityScheme jwtScheme = new OpenApiSecurityScheme
                {
                    Name = "Bearer authentication",
                    Description = "JWT token must be provided. Enter __ONLY__ bearer token below.",
                    BearerFormat = "JWT",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.Http,
                    Scheme = JwtBearerDefaults.AuthenticationScheme,
                    Reference = new OpenApiReference
                    {
                        Id = "Bearer",
                        Type = ReferenceType.SecurityScheme,
                    }
                };
                options.AddSecurityDefinition("Bearer", jwtScheme);
                // <---- JWT Bearer security scheme

                // API KEY security scheme ---->
                OpenApiSecurityScheme apiKeyScheme = new OpenApiSecurityScheme
                {
                    Name = "X-API-KEY",
                    Description = "Enter API KEY below.",
                    In = ParameterLocation.Header,
                    Type = SecuritySchemeType.ApiKey,
                    Scheme = ApiKeyDefaults.AuthenticationScheme,
                    Reference = new OpenApiReference
                    {
                        Id = "ApiKey",
                        Type = ReferenceType.SecurityScheme
                    }
                };
                options.AddSecurityDefinition("ApiKey", apiKeyScheme);
                // <---- API KEY security scheme

                options.AddSecurityRequirement(new OpenApiSecurityRequirement
                {
                    {
                        jwtScheme,
                        new string[]{ }
                    },
                    {
                        apiKeyScheme,
                        new string[]{ }
                    }
                });

            });

            // NTLM Auth
            //builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme)
            //    .AddNegotiate();
            // <---- NTLM Auth

            // JWT Authentication
            //builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme).AddJwtBearer(options => {
            //    options.TokenValidationParameters = new TokenValidationParameters
            //    {
            //        ValidateIssuer = true,
            //        ValidateAudience = true,
            //        ValidateLifetime = true,
            //        ValidateIssuerSigningKey = true,
            //        ValidIssuer = builder.Configuration["Jwt:Issuer"],
            //        ValidAudience = builder.Configuration["Jwt:Audience"],
            //        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
            //    };
            //});
            // <---- JWT Authentication

            // Mixed Auth
            builder.Services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = NegotiateDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
            })
            .AddNegotiate() // <-- must be, negotiate authentication
            .AddJwtBearer(options => // <-- JWT Bearer authentcation
            {
                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    ValidateIssuerSigningKey = true,
                    ValidIssuer = builder.Configuration["Jwt:Issuer"],
                    ValidAudience = builder.Configuration["Jwt:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
                };
                //options.Events = new JwtBearerEvents();
                //// override the challenge behaviour and change the status to 600
                //options.Events.OnChallenge = context =>
                //{
                //    context.HandleResponse();
                //    context.Response.StatusCode = 600;
                //    return Task.CompletedTask;
                //};
            })
            .AddApiKey(options => // <-- API Key authentication, see ApiKey folder for implementation
            {
                options.ApiKey = builder.Configuration["ApiKey:Key"];
                options.OwnerName = builder.Configuration["ApiKey:Owner"];
                string roles = builder.Configuration["ApiKey:Roles"];
                if (roles != null)
                {
                    options.Roles = roles.Split(new char[] { ',', ';' },
                        StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
                }
            });
            // <---- Mixed Auth

            /* ---- I don't know why, I can't explain this ----> */
            builder.Services.AddAuthorization(options =>
            {
                // By default, all incoming requests will be authorized according to the default policy.
                options.FallbackPolicy = options.DefaultPolicy;
            });

            //disable automatic authentication for in-process hosting
            builder.Services.Configure<IISServerOptions>(options =>
            {
                options.AutomaticAuthentication = false;
            });

            //disable automatic authentication for out-of-process hosting
            builder.Services.Configure<IISOptions>(options =>
            {
                options.AutomaticAuthentication = false;
            });
            /* <---- I don't know why, I can't explain this ---- */

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment())
            {
                // Sometimes you want to use swagger only in dev
                //app.UseSwagger();
                //app.UseSwaggerUI();
            }
            // Swagger used always
            app.UseSwagger();
            app.UseSwaggerUI();

            app.UseHttpsRedirection();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllers();

            app.Run();
        }
    }
}