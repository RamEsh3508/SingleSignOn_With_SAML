using System;
using System.Linq;
using AdeNet.Common;
using AdeNet.Common.Components;

namespace AdeNet.Web.Components
{
	internal static class SingleSignOnConfiguration
	{
		#region Internals
		internal static bool IsRequestIssuerConfigured()
		{
			string[] samlRequestIssuers = SystemSettings<SingleSignOnSystemSettings>.Current.SamlRequestIssuer;
			return samlRequestIssuers != null && samlRequestIssuers.Length > 0;
		}

		internal static bool IsAssertionConsumerServiceURLConfigured()
		{
			string[] assertionConsumerServiceURLs = SystemSettings<SingleSignOnSystemSettings>.Current.AssertionConsumerServiceURL;
			return assertionConsumerServiceURLs != null && assertionConsumerServiceURLs.Length > 0;
		}

		internal static ValidateResult IsValidRequestIssuer(string strRequestIssuer)
		{
			string strMessage = string.Format("SAMLAuthnRequest Issuer-Element with value '{0}' does not match the currently configured SamlRequestIssuer in the systemsettings with value '{1}'.",
											  strRequestIssuer, SystemSettings<SingleSignOnSystemSettings>.Current.SamlRequestIssuer);

			if(string.IsNullOrWhiteSpace(strRequestIssuer)) return ValidateResult.Failure(strMessage);

			bool bValid = SystemSettings<SingleSignOnSystemSettings>.Current.SamlRequestIssuer.Any(x => x.StartsWith(strRequestIssuer, StringComparison.CurrentCultureIgnoreCase));
			return bValid ? ValidateResult.Success : ValidateResult.Failure(strMessage);
		}

		internal static string GetAssertionConsumerServiceURLByRequestIssuer(string strRequestIssuer)
		{
			if(string.IsNullOrWhiteSpace(strRequestIssuer)) return string.Empty;
			if(!IsRequestIssuerConfigured()) return string.Empty;
			if(!IsAssertionConsumerServiceURLConfigured()) return string.Empty;

			// Check Array-Lenghts: Must be identical. For each entry in SamlRequestIssuer there must be a corresponding entry at the same index in AssertionConsumerServiceURL.
			string[] samlRequestIssuers = SystemSettings<SingleSignOnSystemSettings>.Current.SamlRequestIssuer;
			string[] assertionConsumerServiceURLs = SystemSettings<SingleSignOnSystemSettings>.Current.AssertionConsumerServiceURL;
			if(samlRequestIssuers.Length != assertionConsumerServiceURLs.Length) return string.Empty;

			// Set default RequestIssuer-Index
			int nIndex = -1;

			// Search for RequestIssuer-Index
			for(int i = 0; i < samlRequestIssuers.Length; i++)
			{
				if(samlRequestIssuers[i].StartsWith(strRequestIssuer, StringComparison.CurrentCultureIgnoreCase)) nIndex = i;
			}

			// RequestIssuer-Index not found
			if(nIndex < 0) return string.Empty;

			return assertionConsumerServiceURLs[nIndex];
		}
		#endregion
	}
}