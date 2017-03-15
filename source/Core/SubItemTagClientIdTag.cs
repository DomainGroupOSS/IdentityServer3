namespace IdentityServer3.Core
{
    public struct SubItemTagClientIdTag
    {
        public const string Token = ":subitemtag:";

        private readonly string _value;

        public SubItemTagClientIdTag(string value)
        {
            _value = value;
        }

        public override string ToString()
        {
            return string.Format("{0}clientid={1}", Token, _value);
        }
    }
}