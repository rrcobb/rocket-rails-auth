#![feature(proc_macro_hygiene, decl_macro)]

#[macro_use] extern crate rocket;

#[get("/")]
fn index() -> &'static str {
    "Hello, world!"
}

// get /login, render login template
// get /signup, render signup template
// post /login, check credentials, issue cookie on good credentials, redirect
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
// T_DO
// - CSRF prevention
// - CORS

fn main() {
    rocket::ignite().mount("/", routes![index]).launch();
}
