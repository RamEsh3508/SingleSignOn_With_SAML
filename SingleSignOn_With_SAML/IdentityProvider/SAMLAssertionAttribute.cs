namespace AdeNet.Web.Components
{
	/// <summary>
	/// Assertion attribute. For further information see: https://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf.
	/// </summary>
	public class SAMLAssertionAttribute
	{
		#region Properties
		/// <summary>
		/// The name of the attribute.
		/// </summary>
		public string Name { get; set; }

		/// <summary>
		/// The value of the attribute.
		/// </summary>
		public string Value { get; set; }
		#endregion
	}
}