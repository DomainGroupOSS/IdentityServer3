using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using Newtonsoft.Json.Linq;

namespace IdentityServer3.Core.Services.Default
{
    /// <summary>
    /// Claims filter for facebook.
    /// </summary>
    public class FacebookClaimsFilter : ClaimsFilterBase
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="FacebookClaimsFilter"/> class.
        /// </summary>
        public FacebookClaimsFilter()
            : this("Facebook")
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="FacebookClaimsFilter"/> class.
        /// </summary>
        /// <param name="provider">The provider this claims filter will operate against.</param>
        public FacebookClaimsFilter(string provider)
            : base(provider)
        {
        }

        /// <summary>
        /// Transforms the claims if this provider is used.
        /// </summary>
        /// <param name="claims">The claims.</param>
        /// <returns></returns>
        protected override IEnumerable<Claim> TransformClaims(IEnumerable<Claim> claims)
        {
            var nameClaim = claims.FirstOrDefault(x => x.Type == "urn:facebook:name");
            var firstNameClaim = claims.FirstOrDefault(x => x.Type == "urn:facebook:first_name");
            var lastNameClaim = claims.FirstOrDefault(x => x.Type == "urn:facebook:last_name");
            var profileImageClaim = claims.FirstOrDefault(x => x.Type == "urn:facebook:picture");

            var list = claims.ToList();

            if (nameClaim != null)
            {
                if (list.All(c => c.Type != Constants.ClaimTypes.Name))
                {
                    list.Add(new Claim(Constants.ClaimTypes.Name, nameClaim.Value));
                }
            }
            if (firstNameClaim != null)
            {
                if (list.All(c => c.Type != Constants.ClaimTypes.GivenName))
                {
                    list.Add(new Claim(Constants.ClaimTypes.GivenName, firstNameClaim.Value));
                }
            }
            if (lastNameClaim != null)
            {
                if (list.All(c => c.Type != Constants.ClaimTypes.FamilyName))
                {
                    list.Add(new Claim(Constants.ClaimTypes.FamilyName, lastNameClaim.Value));
                }
            }
            if (profileImageClaim != null)
            {
                if (list.All(c => c.Type != Constants.ClaimTypes.Picture))
                {
                    var imagePath = JObject.Parse(profileImageClaim.Value);
                    JToken image;
                    imagePath.TryGetValue("data", out image);
                    list.Add(new Claim(Constants.ClaimTypes.Picture, image["url"].Value<string>()));
                }
            }

            return list;
        }
    }
}