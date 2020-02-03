using System;
using System.Web.UI;
using System.Xml.Linq;

namespace AdeNet.Web.Components
{
	[Serializable]
	public class SAMLAuthnRequest
	{
		#region Properties
		internal string SAMLRequest { get; set; }
		internal string RelayState { get; set; }
		internal string HttpMethod { get; set; }
		#endregion

		#region Publics
		public override string ToString()
		{
			return string.Format("HttpMethod: {0}. SAMLRequest: {1}. RelayState: {2}", this.HttpMethod, this.SAMLRequest, this.RelayState);
		}
		#endregion
	}
}