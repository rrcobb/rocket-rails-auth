#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;
use rocket::request::Form;
use rocket::response::Redirect;
use rocket::http::{Cookie, Cookies};
use rocket_contrib::templates::Template;
use serde::{Serialize};

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

#[derive(FromForm, Serialize)]
struct Login {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct EmptyContext {}

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

#[get("/login")]
/// renders login form
fn login() -> Template {
    let context = EmptyContext {};
    Template::render("login", &context)
}

#[get("/signup")]
/// renders signup template
fn signup() -> Template {
    let context = EmptyContext {};
    Template::render("signup", &context)
}


// post /signup, create user, issue cookie on success, redirect
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
        .mount("/", routes![index, login, handle_login, signup]).launch();
}
