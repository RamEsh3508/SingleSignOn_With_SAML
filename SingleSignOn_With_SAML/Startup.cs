using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;

namespace SingleSignOn_With_SAML
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
