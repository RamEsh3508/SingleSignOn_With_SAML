using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Web;
using System.Xml;
using System.Xml.Linq;


namespace AdeNet.Web.Components
{
	public class SAMLAuthnRequestHandler : IHttpHandler
	{
		#region Constants
		private const string SAML_REQUEST_FORM_ELEMENT_ID = "SAMLRequest";
		private const string SAML_RESPONSE_FORM_ELEMENT_ID = "SAMLResponse";
		private const string SAML_RELAYSTATE_FORM_ELEMENT_ID = "RelayState";
		#endregion

		#region Properties
		public bool IsReusable
		{
			get { return false; }
		}
		private SAMLIdentityProvider SAMLIdentityProvider { get; set; }
		#endregion

		#region Publics

		public void InvokeSingleSignOn(HttpContext context)
		{
			try
			{
				// Extract SAMLRequest information from httpRequest
				string strRequestId = string.Format("id-{0}", Guid.NewGuid());

				SAMLAuthnRequest request = GetSignedSamlAuthnRequest(strRequestId, "2.0", "https://www.google.com/", "");

				// Read SingleSignOn Cookie => return value might be null => checked by SAMLIdentityProvider
				UserContext.Current = SingleSignOnCookie.GetSingleSignOnUserInfo(context);

				// Read additional attributes from Cookie, which were added via extender
				IEnumerable<SAMLAssertionAttribute> additionalAttributes = SingleSignOnCookie.GetAttributes(context);

				// Process SAMLAuthnRequest and Signature and create SAMLAuthnResponse
				SAMLIdentityProvider identityProvider = new SAMLIdentityProvider();
				SAMLAuthnResponse response = identityProvider.CreateResponse(request, additionalAttributes == null ? null : additionalAttributes.ToArray());

				// Render self-submitting HTMl-Form to respond to the SAMLAuthnRequest
				RenderSAMLResponse(context, request, response);
			}
			catch(Exception ex)
			{
				AdeNetSingleSignOn.Log.Error(ex);
				context.Response.StatusCode = (int) HttpStatusCode.InternalServerError;
			}
		}

		public SAMLAuthnRequest GetSignedSamlAuthnRequest(string strRequestId, string strVersion, string strDestination, string strIssuer)
		{
			XDocument samlRequestDocument = GetSamlRequestDocument(strRequestId, strVersion, strDestination, strIssuer);
			string strSignedRequest = CreateSignedRequestValue(samlRequestDocument.ToString(), "#" + strRequestId);
			SAMLAuthnRequest request = new SAMLAuthnRequest
			                           {
				                           HttpMethod = "POST",
				                           RelayState = "http://localhost/SAMLServiceProviderSimulator/default.aspx",
				                           SAMLRequest = strSignedRequest
			                           };

			return request;
		}

		public XDocument GetSamlRequestDocument(string strRequestId, string strVersion, string strDestination, string strIssuer)
		{
			XElement authnRequestElement =
				new XElement(SAMLIdentityProvider.SAML_PROTOCOL_NAMESPACE + "AuthnRequest",
				             new XAttribute("Version", strVersion),
				             new XAttribute("IssueInstant", DateTime.UtcNow.ToString("O")),
				             new XAttribute("Destination", strDestination),
				             new XAttribute("Consent", "urn:oasis:names:tc:SAML:2.0:consent:unspecified"),
				             new XAttribute(XNamespace.Xmlns + SAMLIdentityProvider.SAML_PROTOCOL_NAMESPACE_PREFIX, SAMLIdentityProvider.SAML_PROTOCOL_NAMESPACE),
				             new XElement(SAMLIdentityProvider.SAML_ASSERTION_NAMESPACE + "Issuer", strIssuer),
				             new XElement(SAMLIdentityProvider.SAML_PROTOCOL_NAMESPACE + "NameIDPolicy",
				                          new XAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"),
				                          new XAttribute("AllowCreate", true)
				                         )
				            );

			if(strRequestId != null)
			{
				// Add ID-Attribute dynamically to provoke InvalidOperationException in SAMLIdentityProvider with certain tests
				authnRequestElement.Add(new XAttribute("ID", strRequestId));
			}

			return new XDocument(authnRequestElement);
		}


		private string CreateSignedRequestValue(string strSamlRequest, string strReferenceURI)
		{
			X509Certificate2 certificate = this.SAMLIdentityProvider.SAMLCertificateManager.GetAuthnResponseCertificate();

			XmlDocument xmlRequest = new XmlDocument();
			xmlRequest.LoadXml(strSamlRequest);

			SignedXml signedXml = new SignedXml(xmlRequest);
			signedXml.SigningKey = certificate.PrivateKey;
			signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;

			// Add Reference to Request-ID
			Reference reference = new Reference(strReferenceURI);
			reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
			reference.AddTransform(new XmlDsigExcC14NTransform());
			signedXml.AddReference(reference);

			// Add <KeyInfo> to the XML signature
			KeyInfo keyInfo = new KeyInfo();
			KeyInfoX509Data keyInfoData = new KeyInfoX509Data(certificate);
			keyInfo.AddClause(keyInfoData);
			signedXml.KeyInfo = keyInfo;

			// Compute Signature Value
			signedXml.ComputeSignature();

			// Append <Signature> to the XML
			XmlElement elementSignature = signedXml.GetXml();
			XmlElement elementRequest = xmlRequest.DocumentElement;
			if(elementRequest == null) throw new Exception("Request xml document is null.");
			elementRequest.AppendChild(elementSignature);

			return xmlRequest.OuterXml;
		}


		public void ProcessRequest(HttpContext context)
		{
			try
			{
				// Extract SAMLRequest information from httpRequest
				SAMLAuthnRequest request = GetSAMLAuthnRequestFromContext(context);
				AdeNetSingleSignOn.Log.Info("A new SAMLAuthnRequest is being processed.", request);

				// Read SingleSignOn Cookie => return value might be null => checked by SAMLIdentityProvider
				UserContext.Current = SingleSignOnCookie.GetSingleSignOnUserInfo(context);

				// Read additional attributes from Cookie, which were added via extender
				IEnumerable<SAMLAssertionAttribute> additionalAttributes = SingleSignOnCookie.GetAttributes(context);

				// Process SAMLAuthnRequest and Signature and create SAMLAuthnResponse
				SAMLIdentityProvider identityProvider = new SAMLIdentityProvider();
				SAMLAuthnResponse response = identityProvider.CreateResponse(request, additionalAttributes == null ? null : additionalAttributes.ToArray());

				// Render self-submitting HTMl-Form to respond to the SAMLAuthnRequest
				RenderSAMLResponse(context, request, response);
			}
			catch(Exception ex)
			{
				AdeNetSingleSignOn.Log.Error(ex);
				context.Response.StatusCode = (int) HttpStatusCode.InternalServerError;
			}
		}
		#endregion

		#region Privates
		private SAMLAuthnRequest GetSAMLAuthnRequestFromContext(HttpContext context)
		{
			string strSAMLRequest = Encoding.UTF8.GetString(Convert.FromBase64String(context.Request.Form[SAML_REQUEST_FORM_ELEMENT_ID]));
			string strRelayState = context.Request.Form[SAML_RELAYSTATE_FORM_ELEMENT_ID];

			return new SAMLAuthnRequest
			       {
				       HttpMethod = context.Request.HttpMethod,
				       SAMLRequest = strSAMLRequest,
				       RelayState = strRelayState
			       };
		}

		private void RenderSAMLResponse(HttpContext context, SAMLAuthnRequest request, SAMLAuthnResponse response)
		{
			if(context == null) throw new ArgumentNullException("context");
			if(response == null) throw new ArgumentNullException("response");
			if(string.IsNullOrWhiteSpace(response.SAMLAssertionConsumerServiceURL)) throw new Exception("SAMLAssertionConsumerServiceURL cannot be empty.");

			AdeNetSingleSignOn.Log.Info("SAMLAuthnResponse corresponding to the previously processed SAMLAuthnRequest.", request, response);

			string strHtmlForm =
				string.Format(@"
								<html xmlns='http://www.w3.org/1999/xhtml'>
									<body onLoad='document.forms.formSAMLResponse.submit();'>
										<form id='formSAMLResponse' method='POST' action='{0}'>
											<input name='{1}' type='hidden' value='{2}' />
											<input name='{3}' type='hidden' value='{4}' />
										</form>
									</body>
								</html>",
				              response.SAMLAssertionConsumerServiceURL,
				              SAML_RESPONSE_FORM_ELEMENT_ID,
				              Convert.ToBase64String(Encoding.UTF8.GetBytes(response.SAMLResponse)),
				              SAML_RELAYSTATE_FORM_ELEMENT_ID,
				              response.RelayState);

			context.Response.StatusCode = (int) HttpStatusCode.OK;
			context.Response.Write(strHtmlForm);
		}
		#endregion
	}
}