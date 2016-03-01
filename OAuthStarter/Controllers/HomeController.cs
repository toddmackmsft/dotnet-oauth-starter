﻿using OAuthStarter.Auth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;

namespace OAuthStarter.Controllers
{
  public class HomeController : Controller
  {
    // The Azure login authority
    private static string authority = "https://login.microsoftonline.com/common";
    // The application ID from https://apps.dev.microsoft.com
    private static string appId = System.Configuration.ConfigurationManager.AppSettings["ida:AppID"];
    // The application secret from https://apps.dev.microsoft.com
    private static string appSecret = System.Configuration.ConfigurationManager.AppSettings["ida:AppSecret"];

    // The required scopes for our app
    // TODO: Modify this to reflect the scopes your app requires
    private static string[] scopes = { "https://graph.microsoft.com/User.Read" };

    public ActionResult Index()
    {
      // If any message was returned, add it to the ViewBag
      ViewBag.Message = TempData["message"];

      // If any debug data was passed via redirect, copy it
      ViewBag.DebugData = TempData["debug"];

      // Add user info to view if present
      string userName = (string)Session["user_name"];
      string userEmail = (string)Session["user_email"];

      ViewBag.UserLoggedIn = !string.IsNullOrEmpty(userName) && !string.IsNullOrEmpty(userEmail);

      if (!ViewBag.UserLoggedIn)
      {
        // Get the full URL to /OAuth/Authorize
        string authRedirect = Url.Action("Authorize", "OAuth", null, Request.Url.Scheme);

        // The state is used to help protect against cross-site forgery attacks
        string state = Guid.NewGuid().ToString();
        // The nonce value is used to help validate the ID token
        // returned as part of the OpenID flow
        string nonce = Guid.NewGuid().ToString();
        Session["auth_state"] = state;
        Session["auth_nonce"] = nonce;

        // Create an OAuth helper
        OAuthHelper oauthHelper = new OAuthHelper(authority, appId, appSecret);
        string loginUri = oauthHelper.GetAuthorizationUrl(scopes, authRedirect, state, nonce);
        ViewBag.LoginUri = loginUri;

        ViewBag.DebugData = ViewBag.DebugData ?? new Dictionary<string, string>();
        ViewBag.DebugData.Add("State", state);
        ViewBag.DebugData.Add("Nonce", nonce);
        ViewBag.DebugData.Add("Logon URL", loginUri);
      }
      else
      {
        ViewBag.UserName = userName;
        ViewBag.UserEmail = userEmail;
      }

      return View();
    }

    public ActionResult About()
    {
      ViewBag.Message = "Your application description page.";

      return View();
    }

    public ActionResult Contact()
    {
      ViewBag.Message = "Your contact page.";

      return View();
    }

    public ActionResult Error()
    {
      ViewBag.ErrorMessage = TempData["error_message"];
      return View();
    }
  }
}