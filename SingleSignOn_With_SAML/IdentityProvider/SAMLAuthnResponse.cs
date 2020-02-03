using System;
using System.Web.UI;
using System.Xml.Linq;

namespace AdeNet.Web.Components
{
	[Serializable]
	internal class SAMLAuthnResponse
	{
		#region Properties
		internal string SAMLResponse { get; set; }
		internal string RelayState { get; set; }
		internal string SAMLAssertionConsumerServiceURL { get; set; }
		#endregion

		#region Publics
		public override string ToString()
		{
			return string.Format("SAMLResponse: {0}. RelayState: {1}. SAMLAssertionConsumerServiceURL: {2}", this.SAMLResponse, this.RelayState, this.SAMLAssertionConsumerServiceURL);
		}
		#endregion
	}
}