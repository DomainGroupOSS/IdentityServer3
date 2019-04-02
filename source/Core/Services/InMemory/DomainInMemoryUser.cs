using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IdentityServer3.Core.Services.InMemory
{
    public class DomainInMemoryUser
        : InMemoryUser
    {
        public string PasswordlessAuthCode { get; set; }
    }
}
