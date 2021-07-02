#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;
use rocket::request::Form;
use rocket::response::Redirect;
use rocket::http::{Cookie, Cookies};
use rocket_contrib::templates::Template;
use serde::{Serialize};

#[get("/")]
fn index() -> Redirect {
    Redirect::to(uri!(login))
}

#[derive(Serialize)]
struct EmptyContext {}

#[get("/login")]
/// renders login form
fn login() -> Template {
    Template::render("login", &EmptyContext {})
}

#[derive(FromForm, Serialize)]
struct Login {
    email: String,
    password: String,
}

#[post("/login", data = "<login>")]
/// login route: 
/// - check login credentials
/// - redirect back to form if bad credentials
/// - issue session cookie on good credentials
/// - redirect to stored location if there is one
/// - redirect to sign in success page
fn handle_login(login: Form<Login>) -> Template {
    Template::render("success", &*login)
}

#[post("/login", rank = 2)]
fn login_failed() -> Redirect {
    Redirect::to(uri!(login))
}

#[get("/signup")]
/// renders signup template
fn signup() -> Template {
    let context = EmptyContext {};
    Template::render("signup", &context)
}

#[derive(FromForm, Serialize)]
struct Signup {
    email: String,
    password: String,
}

#[post("/signup", data = "<signup>")]
/// creates a new account with the credentials
/// issues a cookie, redirects
fn handle_signup(signup: Form<Signup>) -> Template {
    Template::render("success", &*signup)
}

#[post("/signup", rank = 2)]
fn signup_failed() -> Redirect {
    Redirect::to(uri!(signup))
}


#[get("/authenticated")]
fn authed(mut cookies: Cookies) -> Template {
    let session_token = cookies.get("_twitter_iad_session");
    dbg!(session_token);

    //let hits: u32 = cookies.get("hits").map_or(Ok(0), |c| c.value().parse::<u32>()).unwrap_or(0) + 1;
    //cookies.add(Cookie::new("hits", hits.to_string()));
    // println!("Cookies: ");
    // for c in cookies.iter() {
     //   println!("Name: '{}', Value: '{}'", c.name(), c.value());
    // }
    Template::render("success", &EmptyContext{})
}


// get or post to anything else
//  -> fwd if authenticated
//  -> fwd if unauthenticated for non-authenticated routes
//  -> use static list of authenticated and unauthenticated paths to determine what needs auth and 
//     what to forward where
//  -> check cookie
//      - decrypt it
//      - check that it represents a valid user
//      - (maybe) check that the user is authorized to view the resource
//
// ToDO
// - CSRF prevention
// - CORS
// - remember where to redirect 'back to' after redirect to signin


fn main() {
    rocket::ignite()
        .attach(Template::fairing())
        .mount("/", routes![
            index, 
            login, 
            handle_login, 
            login_failed,
            signup,
            handle_signup,
            signup_failed,
            authed,
        ]).launch();
}
