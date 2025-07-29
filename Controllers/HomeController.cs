using Microsoft.AspNetCore.Mvc;

namespace BackEnd.Controllers
{
    public class HomeController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
    }
}
