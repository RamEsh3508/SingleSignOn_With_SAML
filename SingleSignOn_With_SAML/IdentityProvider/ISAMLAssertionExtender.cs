using System.Collections.Generic;

namespace AdeNet.Web.Components
{
	/// <summary>
	/// This extender allows to add custom information to the assertion of a SAMLAuthnResponse
	/// </summary>
	public interface ISAMLAssertionExtender
	{
		/// <summary>
		/// Gets the assertion attributes to be added to the AttributeStatement section of the assertion
		/// </summary>
		/// <returns>Collection of assertion attributes</returns>
		IEnumerable<SAMLAssertionAttribute> GetAttributes();
	}
}