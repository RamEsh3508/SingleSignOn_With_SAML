using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using System.Web.Hosting;
using System.Xml;
using System.Xml.Linq;
using AdeNet.Web.Components;
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
		#region Constants
		internal static readonly XNamespace SAML_PROTOCOL_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:protocol";
		internal static readonly XNamespace SAML_ASSERTION_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:assertion";
		internal const string SAML_PROTOCOL_NAMESPACE_PREFIX = "saml2p";
		private const string SAML_ASSERTION_NAMESPACE_PREFIX = "saml2";
		#endregion

		#region Fields
		private static readonly X509Certificate2 certificate = new X509Certificate2(HostingEnvironment.MapPath("~/App_Data/SingleSignOn_With_SAML.cer") ?? throw new InvalidOperationException());
		#endregion

		#region Publics
		public void ConfigureAuth(IAppBuilder app)
		{
			HttpContext context = HttpContext.Current;

			app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);

			app.UseCookieAuthentication(new CookieAuthenticationOptions());

			CreateAuthServicesOptions(context);
		}

		public static SAMLAuthnRequest GetSignedSamlAuthnRequest(string strRequestId, string strVersion, string strDestination, string strIssuer)
		{
			XDocument samlRequestDocument = GetSamlRequestDocument(strRequestId, strVersion, strDestination, strIssuer);
			SAMLAuthnRequest request = new SAMLAuthnRequest
			                           {
				                           HttpMethod = "POST",
				                           RelayState = "https://localhost:44335/About.aspx",
				                           SAMLRequest = samlRequestDocument.ToString()
			                           };

			return request;
		}

		public static XDocument GetSamlRequestDocument(string strRequestId, string strVersion, string strDestination, string strIssuer)
		{
			XElement authnRequestElement =
				new XElement(SAML_PROTOCOL_NAMESPACE + "AuthnRequest",
				             new XAttribute("AssertionConsumerServiceURL", "https://localhost:44335/About.aspx"),
				             new XAttribute("Version", strVersion),
				             new XAttribute("IssueInstant", DateTime.UtcNow.ToString("O")),
				             new XAttribute("Destination", "https://login.microsoftonline.com/"),
				             new XAttribute("Format", "transient"),
				             new XAttribute("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"),
				             new XAttribute("AssertionConsumerServiceIndex", "0"),
				             new XAttribute(XNamespace.Xmlns + SAML_PROTOCOL_NAMESPACE_PREFIX, SAML_PROTOCOL_NAMESPACE),
				             new XAttribute(XNamespace.Xmlns + SAML_ASSERTION_NAMESPACE_PREFIX, SAML_ASSERTION_NAMESPACE),
				             new XElement(SAML_ASSERTION_NAMESPACE + "Issuer", "https://localhost:44335/About.aspx"),
				             new XElement(SAML_PROTOCOL_NAMESPACE + "NameIDPolicy",
				                          new XAttribute("AllowCreate", "true"),
				                          new XAttribute("Format", "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"))
				            );

			if(strRequestId != null)
			{
				authnRequestElement.Add(new XAttribute("ID", strRequestId));
			}

			return new XDocument(authnRequestElement);
		}
		#endregion

		#region Privates
		private static void CreateAuthServicesOptions(HttpContext context)
		{
			string strRequestId = Guid.NewGuid().ToString();

			SAMLAuthnRequest request = GetSignedSamlAuthnRequest(strRequestId, "2.0", "https://localhost:44335/About.aspx", "https://sts.windows.net/8b67b292-ebf3-4d29-89a6-47f7971c2e16/");

			//SAMLAuthnResponse response = CreateSuccessResponse(strRequestId, "https://login.microsoftonline.com/", "https://localhost:44335/About.aspx");

			RenderSAMLResponse(context, request, new SAMLAuthnResponse());
		}

		private static XElement CreateResponseElement(string strRequestId, string strIssuerURN)
		{
			return new XElement(SAML_PROTOCOL_NAMESPACE + "Response",
			                    new XAttribute("Destination", "https://localhost:44335/About.aspx"),
			                    new XAttribute("ID", $"Response_{Guid.NewGuid()}"),
			                    new XAttribute("InResponseTo", strRequestId),
			                    new XAttribute("IssueInstant", "https://login.microsoftonline.com/"),
			                    new XAttribute("Version", "2.0"),
			                    new XAttribute(XNamespace.Xmlns + SAML_PROTOCOL_NAMESPACE_PREFIX, SAML_PROTOCOL_NAMESPACE));
		}

		private static void RenderSAMLResponse(HttpContext context, SAMLAuthnRequest request, SAMLAuthnResponse response)
		{
			string strHtmlForm =
				string.Format(@"
								<html xmlns='http://www.w3.org/1999/xhtml'>
									<body onLoad='document.forms[0].submit()'>
										<form id='formSAMLResponse' method='POST' action='{0}'>
											<input name='{1}' type='hidden' value='{2}' />
											<input name='{3}' type='hidden' value='{4}' />
											<input type='submit' value='Submit' />
										</form>
									</body>
								</html>",
				              "https://localhost:44335/About.aspx",
				              "SAMLResponse",
				              Convert.ToBase64String(Encoding.UTF8.GetBytes(request.SAMLRequest)),
				              "RelayState",
				              "8b67b292-ebf3-4d29-89a6-47f7971c2e16");

			context.Response.StatusCode = (int) HttpStatusCode.OK;
			context.Response.Write(strHtmlForm);
		}

		private static string CreateSignedDocumentString(XDocument samlResponseXml, string strElementToSign, string strNamespacePrefix, string strNamespaceURI, string strReferenceURI)
		{
			X509Certificate2 certificate = Startup.certificate;

			string strXPathExpression = string.Format("//{0}:{1}", strNamespacePrefix, strElementToSign);
			XmlNamespaceManager nsMgr = new XmlNamespaceManager(new NameTable());
			nsMgr.AddNamespace(strNamespacePrefix, strNamespaceURI);

			XmlDocument xmlDocumentSignedAssertion = new XmlDocument();
			xmlDocumentSignedAssertion.LoadXml(samlResponseXml.ToString());
			XmlElement xmlElemenResponseAssertion = xmlDocumentSignedAssertion.SelectSingleNode(strXPathExpression, nsMgr) as XmlElement;
			if(xmlElemenResponseAssertion == null)
				throw new Exception(string.Format("Error signing AuthnResponse. Element <{0}:{1} xmlns:{0}=\"{2}\" /> was not found.", strNamespacePrefix, strElementToSign, strNamespacePrefix));
			SignedXml signedAssertionXml = new SignedXml(xmlElemenResponseAssertion);
			signedAssertionXml.SigningKey = certificate.PrivateKey;
			signedAssertionXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

			// Add Reference to Request-ID
			Reference reference = new Reference(strReferenceURI);
			reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
			reference.AddTransform(new XmlDsigExcC14NTransform("xs"));
			signedAssertionXml.AddReference(reference);

			// Add <KeyInfo> to the XML signature
			KeyInfo keyInfo = new KeyInfo();
			KeyInfoX509Data keyInfoData = new KeyInfoX509Data(certificate);
			keyInfo.AddClause(keyInfoData);
			signedAssertionXml.KeyInfo = keyInfo;

			// Compute Signature Value
			signedAssertionXml.ComputeSignature();

			// Get Issuer Element
			XmlElement xmlElementResponseAssertionIssuer = xmlElemenResponseAssertion.FirstChild as XmlElement;
			if(xmlElementResponseAssertionIssuer == null) throw new Exception("Error signing AuthnResponse. Element Issuer was not found.");

			// Append <Signature> to the XML
			XmlElement elementSignature = signedAssertionXml.GetXml();
			xmlElemenResponseAssertion.InsertAfter(elementSignature, xmlElementResponseAssertionIssuer);

			return xmlDocumentSignedAssertion.OuterXml;
		}

		private static SAMLAuthnResponse CreateAuthnResponse(string strIssuer, string strResponseString, string strRelayState)
		{
			return new SAMLAuthnResponse
			       {
				       SAMLResponse = strResponseString,
				       RelayState = strRelayState
			       };
		}

		private Saml2AuthenticationOptions ConfigSAML()
		{
			string strReturnUrl = "https://localhost:44335/About.aspx";

			Saml2AuthenticationOptions authServicesOptions = new Saml2AuthenticationOptions(false)
			                                                 {
				                                                 SPOptions = new SPOptions
				                                                             {
					                                                             EntityId = new EntityId("https://sts.windows.net/8b67b292-ebf3-4d29-89a6-47f7971c2e16/"),
					                                                             ReturnUrl = new Uri(strReturnUrl)
				                                                             }
			                                                 };

			IdentityProvider idp = new IdentityProvider(new EntityId("https://sts.windows.net/8b67b292-ebf3-4d29-89a6-47f7971c2e16/"), authServicesOptions.SPOptions)
			                       {
				                       AllowUnsolicitedAuthnResponse = true,
				                       Binding = Saml2BindingType.HttpRedirect,
				                       SingleSignOnServiceUrl = new Uri("https://login.microsoftonline.com/8b67b292-ebf3-4d29-89a6-47f7971c2e16/saml2")
			                       };

			idp.SigningKeys.AddConfiguredKey(new X509Certificate2(HostingEnvironment.MapPath("~/App_Data/SingleSignOn_With_SAML.cer") ?? throw new InvalidOperationException()));

			authServicesOptions.IdentityProviders.Add(idp);

			return authServicesOptions;
		}
		#endregion
	}
}