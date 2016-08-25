namespace IdentityServer3.Core.Models
{
    public enum AuthenticationFailedCode
    {
        None,
        AccountClosed,
        AccountNotConfiguredWithCertificates,
        AccountNotConfiguredWithAuthenticator,
        AccountNotConfiguredWithMobilePhone,
        AccountRequiresSecondFactorToAuthenticate,
        AccountNotVerified,
        FailedLoginAttemptsExceeded,
        InvalidCredentials,
        InvalidPasswordlessCodes,
        LoginNotAllowed,
        PasswordlessCodeOrSessionNotFound
    }
}