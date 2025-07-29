using Microsoft.AspNetCore.Http;
using System.Security.Claims;
using System.Threading.Tasks;

namespace BackEnd
{
    public class SkipAuthorizationMiddleware
    {
        private readonly RequestDelegate _next;

        public SkipAuthorizationMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Ensure that we set a principal with at least an empty identity
            // This can prevent errors in other parts of the pipeline that may expect a User with a valid Identity.
            context.User = new ClaimsPrincipal(new ClaimsIdentity());

            // Continue to the next middleware in the pipeline
            await _next(context);
        }
    }
}
