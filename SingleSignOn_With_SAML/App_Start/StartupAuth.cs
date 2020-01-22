using System;
using System.Security.Cryptography.X509Certificates;
using System.Web.Hosting;
using Microsoft.Owin.Extensions;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Owin;
using Sustainsys.Saml2;
using Sustainsys.Saml2.Configuration;
using Sustainsys.Saml2.Metadata;
using Sustainsys.Saml2.Owin;
using Sustainsys.Saml2.WebSso;

namespace SingleSignOn_With_SAML
{
	public partial class Startup
	{
		#region Publics
		public void ConfigureAuth(IAppBuilder app)
		{
			app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

			app.UseCookieAuthentication(new CookieAuthenticationOptions());

			app.UseSaml2Authentication(CreateSaml2Options());

			app.UseStageMarker(PipelineStage.Authenticate);
		}
		#endregion

		#region Privates
		private Saml2AuthenticationOptions CreateSaml2Options()
		{
			SPOptions spOptions = new SPOptions
			                      {
				                      EntityId = new EntityId("https://sts.windows.net/8b67b292-ebf3-4d29-89a6-47f7971c2e16/"),
				                      ReturnUrl = new Uri("https://localhost:44335/")
			                      };

			AttributeConsumingService attributeConsumingService = new AttributeConsumingService
			                                                      {
				                                                      IsDefault = true,
				                                                      ServiceNames = { new LocalizedName("Saml2", "en") }
			                                                      };

			attributeConsumingService.RequestedAttributes.Add(
			                                                  new RequestedAttribute("urn:password")
			                                                  {
				                                                  FriendlyName = "AzureADTest",
				                                                  IsRequired = true,
				                                                  NameFormat = RequestedAttribute.AttributeNameFormatUri
			                                                  });

			attributeConsumingService.RequestedAttributes.Add(
			                                                  new RequestedAttribute("Minimal"));

			spOptions.AttributeConsumingServices.Add(attributeConsumingService);

			Saml2AuthenticationOptions Saml2Options = new Saml2AuthenticationOptions(false)
			                                          {
				                                          SPOptions = spOptions
			                                          };

			IdentityProvider idp = new IdentityProvider(new EntityId("https://sts.windows.net/8b67b292-ebf3-4d29-89a6-47f7971c2e16/"), spOptions)
			                       {
				                       AllowUnsolicitedAuthnResponse = true,
				                       Binding = Saml2BindingType.HttpRedirect,
				                       SingleSignOnServiceUrl = new Uri("https://localhost:44335/")
			                       };

			idp.SigningKeys.AddConfiguredKey(new X509Certificate2(HostingEnvironment.MapPath("~/App_Data/AzureADTest.cer") ?? throw new InvalidOperationException()));

			Saml2Options.IdentityProviders.Add(idp);

			return Saml2Options;
		}
		#endregion
	}
}