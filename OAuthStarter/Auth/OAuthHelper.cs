using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;
using System.Web;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace OAuthStarter.Auth
{
  public class OAuthHelper
  {
    // The v2 app model endpoints
    private static string authEndpoint = "/oauth2/v2.0/authorize";
    private static string tokenEndpoint = "/oauth2/v2.0/token";

    // This is the logon authority
    // i.e. https://login.microsoftonline.com/common
    public string Authority { get; set; }
    // This is the application ID obtained from registering at
    // https://apps.dev.microsoft.com
    public string AppId { get; set; }
    // This is the application secret obtained from registering at
    // https://apps.dev.microsoft.com
    public string AppSecret { get; set; }

    public OAuthHelper(string authority, string appId, string appSecret)
    {
      Authority = authority;
      AppId = appId;
      AppSecret = appSecret;
    }

    // Builds the authorization URL where the app sends the user to sign in
    public string GetAuthorizationUrl(string[] scopes, string redirectUri, string state, string nonce)
    {
      // Start with the base URL
      UriBuilder authUrl = new UriBuilder(this.Authority + authEndpoint);

      authUrl.Query =
        "response_type=code+id_token" +
        "&scope=openid+profile+email+offline_access+" + GetEncodedScopes(scopes) +
        "&state=" + state +
        "&nonce=" + nonce +
        "&client_id=" + this.AppId +
        "&redirect_uri=" + HttpUtility.UrlEncode(redirectUri) +
        "&response_mode=form_post";

      return authUrl.ToString();
    }

    private string GetEncodedScopes(string[] scopes)
    {
      string encodedScopes = string.Empty;
      foreach (string scope in scopes)
      {
        if (!string.IsNullOrEmpty(encodedScopes)) { encodedScopes += '+'; }
        encodedScopes += HttpUtility.UrlEncode(scope);
      }
      return encodedScopes;
    }

    // Makes a POST request to the token endopoint to get an access token using either
    // an authorization code or a refresh token. This will also add the tokens
    // to the local cache.
    public async Task<TokenRequestSuccessResponse> GetTokensFromAuthority(string grantType, string grantParameter, string redirectUri, HttpSessionStateBase session)
    {
      // Build the token request payload
      FormUrlEncodedContent tokenRequestForm = new FormUrlEncodedContent(
        new[]
        {
          new KeyValuePair<string,string>("grant_type", grantType),
          new KeyValuePair<string,string>("code", grantParameter),
          new KeyValuePair<string,string>("client_id", this.AppId),
          new KeyValuePair<string,string>("client_secret", this.AppSecret),
          new KeyValuePair<string,string>("redirect_uri", redirectUri)
        }
      );

      using (HttpClient httpClient = new HttpClient())
      {
        string requestString = tokenRequestForm.ReadAsStringAsync().Result;
        StringContent requestContent = new StringContent(requestString);
        requestContent.Headers.ContentType = new MediaTypeHeaderValue("application/x-www-form-urlencoded");

        // Set up the HTTP POST request
        HttpRequestMessage tokenRequest = new HttpRequestMessage(HttpMethod.Post, this.Authority + tokenEndpoint);
        tokenRequest.Content = requestContent;
        tokenRequest.Headers.UserAgent.Add(new ProductInfoHeaderValue("OAuthStarter", "1.0"));
        tokenRequest.Headers.Add("client-request-id", Guid.NewGuid().ToString());
        tokenRequest.Headers.Add("return-client-request-id", "true");

        // Send the request and read the JSON body of the response
        HttpResponseMessage response = await httpClient.SendAsync(tokenRequest);
        JObject jsonResponse = JObject.Parse(response.Content.ReadAsStringAsync().Result);
        JsonSerializer jsonSerializer = new JsonSerializer();

        if (response.IsSuccessStatusCode)
        {
          // Parse the token response
          TokenRequestSuccessResponse s = (TokenRequestSuccessResponse)jsonSerializer.Deserialize(
            new JTokenReader(jsonResponse), typeof(TokenRequestSuccessResponse));

          // Save the tokens
          SaveUserTokens(session, s);
          return s;
        }
        else
        {
          // Parse the error response
          TokenRequestErrorResponse e = (TokenRequestErrorResponse)jsonSerializer.Deserialize(
            new JTokenReader(jsonResponse), typeof(TokenRequestErrorResponse));

          // Throw the error description
          throw new Exception(e.Description);
        }
      }
    }

    public void SaveUserTokens(HttpSessionStateBase session, TokenRequestSuccessResponse tokens)
    {
      // Just save the tokens in the session
      // This works for a demo app, but to be more fault tolerant and secure
      // production apps should explore other storage options, such as a secured
      // database

      // The ID token can be parsed to get the user's ObjectId, which is a unique
      // identifier that can be used as a key to store the user's tokens
      // E.g. OpenIdToken idToken = OpenIdToken.ParseOpenIdToken(tokens.IdToken);

      session["access_token"] = tokens.AccessToken;
      session["refresh_token"] = tokens.RefreshToken;
      // Expire token slightly early (5 minutes) to avoid
      // problems with inconsistencies in clock times
      session["token_expires"] = DateTime.UtcNow.AddSeconds(Int32.Parse(tokens.ExpiresIn) - 300);
    }

    public async Task<string> GetUserAccessToken(HttpSessionStateBase session, string redirectUri)
    {
      if (null == session["access_token"] || null == session["token_expires"])
        return string.Empty;

      string accessToken = (string)session["access_token"];
      DateTime expireTime = (DateTime)session["token_expires"];

      if (expireTime < DateTime.UtcNow)
      {
        // Token is expired, request a new one with the refresh token
        string refreshToken = (string)session["refresh_token"];
        if (string.IsNullOrEmpty(refreshToken))
        {
          // No refresh token
          return string.Empty;
        }

        var response = await GetTokensFromAuthority("refresh_token", refreshToken, redirectUri, session);
        return response.AccessToken;
      }
      else
      {
        // Token is still good, return it
        return accessToken;
      }
    }

    public void Logout(HttpSessionStateBase session)
    {
      session.Remove("user_name");
      session.Remove("user_email");
      session.Remove("access_token");
      session.Remove("refresh_token");
      session.Remove("token_expires");
    }
  }
}