using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;

namespace AdeNet.Web.Components
{
	/// <summary>
	/// 
	/// </summary>
	internal interface ISAMLCertificateManager
	{
		bool IsValidAuthnRequestSignature(SignedXml signedSamlRequestXml, X509Certificate2 signatureCertificate);
		bool IsValidAuthnRequestCertificate(X509Certificate2 signatureCertificate);
		bool IsAuthorizedAuthnRequestCertificate(X509Certificate2 signatureCertificate);
		X509Certificate2 GetAuthnResponseCertificate();
	}
}