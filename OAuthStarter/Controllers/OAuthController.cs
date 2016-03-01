using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using OAuthStarter.Auth;

namespace OAuthStarter.Controllers
{
  public class OAuthController : Controller
  {
    // The Azure login authority
    private static string authority = "https://login.microsoftonline.com/common";
    // The application ID from https://apps.dev.microsoft.com
    private static string appId = System.Configuration.ConfigurationManager.AppSettings["ida:AppID"];
    // The application secret from https://apps.dev.microsoft.com
    private static string appSecret = System.Configuration.ConfigurationManager.AppSettings["ida:AppSecret"];

    public async Task<ActionResult> Authorize()
    {
      Dictionary<string,string> debug = new Dictionary<string, string>();

      string authState = Request.Params["state"];
      string expectedState = (string)Session["auth_state"];
      Session.Remove("auth_state");

      debug.Add("Returned auth state", authState);
      debug.Add("Expected auth state", expectedState);

      // Make sure that the state passed by the caller matches what we expect
      if (!authState.Equals(expectedState))
      {
        TempData["error_message"] = "The auth state did not match the expected value. Please try again.";
        return RedirectToAction("Error", "Home");
      }

      string authCode = Request.Params["code"];
      string idToken = Request.Params["id_token"];

      // Make sure we got back an auth code and ID token
      if (string.IsNullOrEmpty(authCode) || string.IsNullOrEmpty(idToken))
      {
        // If not, check the error and error_desription parameters for more information
        string error = Request.Params["error"];
        string error_description = Request.Params["error_description"];

        if (string.IsNullOrEmpty(error) && string.IsNullOrEmpty(error_description))
        {
          TempData["error_message"] = "Missing authorization code and/or ID token from redirect.";
        }
        else
        {
          TempData["error_message"] = string.Format("Error: {0} - {1}", error, error_description);
        }

        return RedirectToAction("Error", "Home");
      }

      debug.Add("Authorization code", authCode);
      debug.Add("ID token", idToken);

      // Check the nonce in the ID token against what we expect
      string nonce = (string)Session["auth_nonce"];
      Session.Remove("auth_nonce");

      OpenIdToken userId = OpenIdToken.ParseOpenIdToken(idToken);
      if (!userId.Validate(nonce))
      {
        TempData["error_message"] = "Invalid ID token.";
        return RedirectToAction("Error", "Home");
      }

      // Fill in user's information from token
      Session["user_name"] = userId.Name;
      Session["user_email"] = userId.PreferredUsername;

      // Request an access token
      OAuthHelper oauthHelper = new OAuthHelper(authority, appId, appSecret);
      string redirectUri = Url.Action("Authorize", "OAuth", null, Request.Url.Scheme);
      try
      {
        var response = await oauthHelper.GetTokensFromAuthority("authorization_code",
          authCode, redirectUri, Session);

        debug.Add("Access Token", response.AccessToken);
        debug.Add("Refresh Token", response.RefreshToken);
      }
      catch (Exception ex)
      {
        TempData["error_message"] = string.Format("Error requesting access token: {0}", ex.Message);
        return RedirectToAction("Error", "Home");
      }

      // Pass debug in TempData to preserve information
      // over the redirect
      TempData["debug"] = debug;

      return Redirect("/");
    }

    public ActionResult Logout()
    {
      OAuthHelper oauthHelper = new OAuthHelper(authority, appId, appSecret);
      oauthHelper.Logout(Session);
      TempData["message"] = "Logged out";
      return Redirect("/");
    }
  }
}