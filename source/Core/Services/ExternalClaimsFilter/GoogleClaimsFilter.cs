/*
 * Copyright 2014, 2015 Dominick Baier, Brock Allen
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;

namespace IdentityServer3.Core.Services.Default
{
    /// <summary>
    /// Claims filter for google.
    /// </summary>
    public class GoogleClaimsFilter : ClaimsFilterBase
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="FacebookClaimsFilter"/> class.
        /// </summary>
        public GoogleClaimsFilter()
            : this("Google")
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="FacebookClaimsFilter"/> class.
        /// </summary>
        /// <param name="provider">The provider this claims filter will operate against.</param>
        public GoogleClaimsFilter(string provider)
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
            var nameClaim = claims.FirstOrDefault(x => x.Type == "urn:google:name");
            var firstNameClaim = claims.FirstOrDefault(x => x.Type == "urn:google:given_name");
            var lastNameClaim = claims.FirstOrDefault(x => x.Type == "urn:google:surname");

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
            return list;
        }
    }
}
