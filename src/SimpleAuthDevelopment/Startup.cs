using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace SimpleAuthDevelopment
{
    public class Startup
    {
        public Startup(IHostingEnvironment env)
        {
            var builder = new ConfigurationBuilder()
                .SetBasePath(env.ContentRootPath)
                .AddJsonFile("appsettings.json", optional: true, reloadOnChange: true)
                .AddJsonFile($"appsettings.{env.EnvironmentName}.json", optional: true)
                .AddEnvironmentVariables();
            Configuration = builder.Build();
        }

        public IConfigurationRoot Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {

            services.AddSingleton<Microsoft.AspNetCore.Http.IHttpContextAccessor, Microsoft.AspNetCore.Http.HttpContextAccessor>();

            services.AddAuthentication(
                delegate (Microsoft.AspNetCore.Authentication.SharedAuthenticationOptions options)
                {
                    // options.SignInScheme = "foo";
                }
            );

            // Add framework services.
            // services.AddMvc();
            services.AddMvc(
                delegate (Microsoft.AspNetCore.Mvc.MvcOptions config)
                {
                    Microsoft.AspNetCore.Authorization.AuthorizationPolicy policy = new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
                                     .RequireAuthenticatedUser()
                                     // .AddRequirements( new NoBannedIPsRequirement(new HashSet<string>() { "127.0.0.1", "0.0.0.1" } ))
                                     .Build();

                    config.Filters.Add(new Microsoft.AspNetCore.Mvc.Authorization.AuthorizeFilter(policy));
                }
            );


        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();





            /*
            var tokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
            {
                // The signing key must match!
                ValidateIssuerSigningKey = true,
                // IssuerSigningKey = signingKey,

                // Validate the JWT Issuer (iss) claim
                ValidateIssuer = true,
                ValidIssuer = "ExampleIssuer",

                // Validate the JWT Audience (aud) claim
                ValidateAudience = true,
                ValidAudience = "ExampleAudience",

                // Validate the token expiry
                ValidateLifetime = true,

                // If you want to allow a certain amount of clock drift, set that here:
                ClockSkew = TimeSpan.Zero,
            };
            */

            var bearerOptions = new JwtBearerOptions()
            {
                AutomaticAuthenticate = true,
                AutomaticChallenge = true,
                // TokenValidationParameters = tokenValidationParameters,
                // Events = new CustomBearerEvents()
            };

            // Optional 
            // bearerOptions.SecurityTokenValidators.Clear();
            // bearerOptions.SecurityTokenValidators.Add(new MyTokenHandler());


            app.UseJwtBearerAuthentication(bearerOptions);








            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}
