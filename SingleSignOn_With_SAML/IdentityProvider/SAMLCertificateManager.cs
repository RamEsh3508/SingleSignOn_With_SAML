using System;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using AdeNet.Common;
using AdeNet.Common.Components;

namespace AdeNet.Web.Components
{
	internal class SAMLCertificateManager : ISAMLCertificateManager
	{
		#region Publics
		public bool IsValidAuthnRequestSignature(SignedXml signedSamlRequestXml, X509Certificate2 signatureCertificate)
		{
			if(signedSamlRequestXml == null) throw new ArgumentNullException("signedSamlRequestXml");
			if(signatureCertificate == null) throw new ArgumentNullException("signatureCertificate");

			return signedSamlRequestXml.CheckSignature(signatureCertificate, true);
		}

		public bool IsValidAuthnRequestCertificate(X509Certificate2 signatureCertificate)
		{
			if(signatureCertificate == null) throw new ArgumentNullException("signatureCertificate");

			return signatureCertificate.Verify();
		}

		public bool IsAuthorizedAuthnRequestCertificate(X509Certificate2 signatureCertificate)
		{
			if(signatureCertificate == null) throw new ArgumentNullException("signatureCertificate");

			string[] strSamlRequestCertificateAuthorities = SystemSettings<SingleSignOnSystemSettings>.Current.SamlRequestCertificateAuthorities;
			if(strSamlRequestCertificateAuthorities == null || strSamlRequestCertificateAuthorities.Length == 0)
			{
				AdeNetSingleSignOn.Log.Warn(
				                            "Es wurden keine SAML Request Certificate-Authorities in den Systemeinstellungen (INI) hinterlegt. Single-Sign-On ist deaktiviert, bis die authorisierten Zertifikats-Aussteller korrekt konfiguriert sind.");
				return false;
			}

			return strSamlRequestCertificateAuthorities.Any(authority => signatureCertificate.IssuerName.Name == authority);
		}

		public X509Certificate2 GetAuthnResponseCertificate()
		{
			string strResponseCertificate = SystemSettings<SingleSignOnSystemSettings>.Current.SamlResponseCertificate;

			X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine);
			X509Certificate2 certificate = null;
			try
			{
				store.Open(OpenFlags.ReadOnly);

				// Find Certificate by 
				X509Certificate2Collection collection = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, strResponseCertificate, false);
				certificate = collection[0];
				if(certificate == null)
				{
					collection = store.Certificates.Find(X509FindType.FindByIssuerDistinguishedName, strResponseCertificate, false);
					certificate = collection[0];
				}
			}
			catch(Exception ex)
			{
				string strMessage = string.Format("Error loading Certificate with common name '{0}' in certifiacte store with name 'Store.My' on the store location 'StoreLocation.LocalMachine'.",
				                                  strResponseCertificate);
				AdeNetSingleSignOn.Log.Error(strMessage, ex);
			}
			finally
			{
				store.Close();
			}

			if(certificate == null) throw new Exception(string.Format("Certificate '{0}' not found in the local certificate store", strResponseCertificate));

			return certificate;
		}
		#endregion
	}
}