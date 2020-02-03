namespace AdeNet.Web.Components
{
	internal class SAMLTopLevelStatusCode
	{
		#region Constants
		/// <summary>
		/// The request succeeded. Additional information MAY be returned in the <StatusMessage/> and/or <StatusDetail/> elements.
		/// </summary>
		internal const string SAML_TOPLEVEL_STATUSCODE_SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success";

		/// <summary>
		/// The request could not be performed due to an error on the part of the requester.
		/// </summary>
		internal const string SAML_TOPLEVEL_STATUSCODE_REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester";

		/// <summary>
		/// The request could not be performed due to an error on the part of the SAML responder or SAML authority.
		/// </summary>
		internal const string SAML_TOPLEVEL_STATUSCODE_RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder";

		/// <summary>
		/// The SAML responder could not process the request because the version of the request message was incorrect.
		/// </summary>
		internal const string SAML_TOPLEVEL_STATUSCODE_VERSION_MISMATCH = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch";
		#endregion
	}
}