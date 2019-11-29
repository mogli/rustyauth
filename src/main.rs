mod db;

#[macro_use]
extern crate rouille;
extern crate rand;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

use rouille::Request;
use rouille::Response;
use std::collections::HashMap;
use std::io;
use std::sync::Mutex;

use postgres::{Connection, TlsMode};

use bcrypt::{hash, verify, DEFAULT_COST};

use clap::{App, Arg};

#[derive(Debug, Clone)]
struct SessionData {
    login: String,
}

fn main() {
    let matches = App::new("OAuth2 authorization server.")
        .version("0.1.0")
        .author("Martin Weidner <martin.weidner.wt@gmail.com>")
        .arg(Arg::with_name("port")
                 .short("p")
                 .long("port")
                 .takes_value(true)
                 .help("Port that server listens on"))
        .arg(Arg::with_name("dbaddress")
                 .short("d")
                 .long("db_address")
                 .takes_value(true)
                 .help("url to postgres dataase"))
        .arg(Arg::with_name("initdb")
                 .short("i")
                 .long("init-db")
                 .takes_value(false)
                 .help("Initialize the database schema and generates an initial user with random credentials"))
        .arg(Arg::with_name("cleanup")
                 .short("c")
                 .long("cleanup")
                 .takes_value(false)
                 .help("Used with --init-db. Will delete existing schema and all users/clients"))
        .get_matches();

    let db_uri: String = format!("postgresql://{}", matches.value_of("dbaddress").unwrap());

    if matches.is_present("initdb") {
        println!("- Initializing database schema.");
        let conn = Connection::connect(db_uri.clone(), TlsMode::None).unwrap();
        if matches.is_present("cleanup") {
            println!("- Dropping existing schema.");
            conn.execute("drop schema if exists rustyauth cascade;", &[])
                .unwrap();
        }
        db::init_database_schema(&conn);
        let pw: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();
        adduser(
            &conn,
            &"admin".to_string(),
            &pw,
            &"admin@localhost".to_string(),
        );
        println!("- Added initial user: admin:{}", pw);
    }
    let port: i32 = matches.value_of("port").unwrap().parse::<i32>().unwrap();
    let address: String = format!("localhost:{}", port);

    println!("Listening on {}", address.clone());
    let session_storage: Mutex<HashMap<String, SessionData>> = Mutex::new(HashMap::new());

    rouille::start_server(address, move |request| {
        rouille::log(&request, io::stdout(), || {
            rouille::session::session(request, "SID", 3600, |session| {
                let mut session_data = if session.client_has_sid() {
                    if let Some(data) = session_storage.lock().unwrap().get(session.id()) {
                        Some(data.clone())
                    } else {
                        None
                    }
                } else {
                    None
                };
                let response = handle_route(&request, &mut session_data, &db_uri.clone());
                if let Some(d) = session_data {
                    session_storage
                        .lock()
                        .unwrap()
                        .insert(session.id().to_owned(), d);
                } else if session.client_has_sid() {
                    session_storage.lock().unwrap().remove(session.id());
                }
                response
            })
        })
    });
}

#[allow(unreachable_code)]
fn handle_route(
    request: &Request,
    session_data: &mut Option<SessionData>,
    db_uri: &String,
) -> Response {
    router!(request,
        (POST) (/login) => {
            let data = try_or_400!(post_input!(request,{
                login: String,
                password: String,
            }));
            println!("Login attempt with login {:?}", data.login);
            let conn = Connection::connect(db_uri.clone(), TlsMode::None).unwrap();
            let valid_password = verify_login(&conn, &data.login, &data.password);
            if valid_password {
                *session_data = Some(SessionData{ login: data.login });
                return Response::redirect_303("/");
            } else {
                return Response::html("Wrong login/password.");
            }
        },
        (POST) (/logout) => {
            *session_data = None;
            return Response::html(r#"Logout successful.
                                        <a href="/"> Click here to go to the home</a>"#);
        },
        _=>()
    );

    if let Some(session_data) = session_data.as_ref() {
        handle_route_logged_in(request, session_data, &db_uri)
    } else {
        // not logged in
        router!(request,
            (GET) (/) => {
                Response::html(r#"
            <form action="/login" method="POST">
              <input type="text" name="login" placeholder="Login" />
              <input type="password" name="password" placeholder="Password" />
              <button type="submit">Login</button>
            </form>
            "#)
            },
            // token endpoint
            (POST) (/oauth/token) => {
                let data = try_or_400!(post_input!(request,{
                    client_id: String,
                    client_secret: String,
                    grant_type: String,
                    code: String,
                    token_format: String,
                    redirect_uri: String,
                }));
                let conn = Connection::connect(db_uri.clone(), TlsMode::None).unwrap();
                if verify_client(&conn, &data.client_id, &data.client_secret) && verify_code_for_client(&conn, &data.client_id, &data.code, &data.redirect_uri) {
                    let return_info = json::object!{
                        "access_token" => "blubs",
                        "token_type" => "bearer",
                        "id_token" => "blubs",
                        "refresh_token" => "blubs",
                        "expires_in" => 43199,
                        "scope" => "openid",
                        "jti" => "blubs"
                    };
                   return Response::json(&return_info.dump());
                }
                return Response::empty_404();
            },
            _ => {
                // any route
                Response::redirect_303("/")
            }
        )
    }
}

fn handle_route_logged_in(
    request: &Request,
    _session_data: &SessionData,
    db_uri: &String,
) -> Response {
    router!(request,
        (GET) (/) =>{
            Response::html(r#"<p>You are now logged in. A session cookie keeps you logged in. <a href="/private"> To private area </a></p>
                <p><a href="/users">User Manangement</a></p>
                <p><a href="/clients">Client Manangement</a></p>
                <form action="/logout" method="POST">
                    <button>Logout</button>
                </form>"#)
        },
        (GET) (/private) => {
            Response::html(r#"You are in the private area! <a href="/">Go back</a>"#)
        },
        (GET) (/users) => {
            Response::html(r#"
            <form action="/users/add" method="POST">
              <input type="text" name="login" placeholder="Login" />
              <input type="text" name="email" placeholder="eMail" />
              <input type="password" name="password" placeholder="Password" />
              <button type="submit">Add User</button>
            </form>
            "#)
        },
        (POST) (/users/add) => {
            let data = try_or_400!(post_input!(request,{
                login: String,
                password: String,
                email: String,
            }));
            let conn = Connection::connect(db_uri.clone(), TlsMode::None).unwrap();
            // todo: check if user exists!
            adduser(&conn, &data.login, &data.password, &data.email);
            /*
              let hashed = hash(data.password, DEFAULT_COST).unwrap();
              conn.execute("insert into rustyauth.users (username, password, email, created_on) values($1, $2, $3, current_timestamp)", &[&data.login, &hashed, &data.email]).unwrap();
            */
            println!("User {:?} added user {:?}", _session_data.login, data.login);
            Response::html(r#"<p>User successfully created.</p><p><a href="/users">User Manangement</a></p>"#)
        },
        (GET) (/clients) => {
            Response::html(r#"
            <form action="/clients/add" method="POST">
              <input type="text" name="client_name" placeholder="Client Name" />
              <input type="text" name="url" placeholder="URL" />
              <button type="submit">Add Client</button>
            </form>
            "#)
        },
        (POST) (/clients/add) => {
            let data = try_or_400!(post_input!(request,{
                client_name: String,
                url: String,
            }));
            let client_id = uuid::Uuid::new_v4().to_string();
            let client_secret: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();
            let hashed = hash(client_secret.clone(), DEFAULT_COST).unwrap();
            let conn = Connection::connect(db_uri.clone(), TlsMode::None).unwrap();
            conn.execute("insert into rustyauth.clients (client_id, client_name, client_secret, url, created_on) values ($1, $2, $3, $4, current_timestamp); ", &[&client_id, &data.client_name, &hashed, &data.url]).unwrap();
            let html_response = format!("<p>Client successfully created.</p> <p>Client-id: {}</p><p>Client-secret: {}</p> <p><a href=\"/clients\">Client Manangement</a></p>", client_id, client_secret);
            Response::html(html_response)
        },
        (GET) (/oauth/authorize) => {
            let client_id: String = request.get_param("client_id").unwrap();
            let redirect_uri: String = request.get_param("redirect_uri").unwrap();
            let scopes: String = request.get_param("scope").unwrap();
            let conn = Connection::connect(db_uri.clone(), TlsMode::None).unwrap();
            let code: String = generate_code(&conn, &client_id, &_session_data.login, &redirect_uri, &scopes);
            let redirect: String = format!("{}?code={}", redirect_uri, code);
            Response::redirect_303(redirect)
        },
        _ => Response::empty_404()
    )
}

fn generate_code(
    conn: &Connection,
    client_id: &String,
    username: &String,
    redirect_uri: &String,
    scopes: &String,
) -> String {
    let rows = conn
        .query(
            "select user_id from rustyauth.users where username=$1;",
            &[username],
        )
        .unwrap();
    if rows.len() == 1 {
        let user_id: i32 = rows.get(0).get(0);
        println!("Loading url for client {} and user {}", client_id, username);
        let rows2 = conn
            .query(
                "select url from rustyauth.clients where client_id=$1;",
                &[client_id],
            )
            .unwrap();
        if rows2.len() == 1 {
            let client_url: String = rows2.get(0).get(0);
            if redirect_uri.contains(&client_url) {
                let code: String = uuid::Uuid::new_v4().to_string();
                conn.execute("insert into rustyauth.client_code (client_id, user_id, code, scopes, created_on) values ($1, $2, $3, $4, current_timestamp);", &[client_id, &user_id, &code, &scopes]).unwrap();
                return code;
            } else {
                println!("urls mismatch");
            }
        } else {
            println!("did not find client");
        }
    }
    "".to_string()
}

fn adduser(conn: &Connection, login: &String, password: &String, email: &String) {
    let hashed = hash(password, DEFAULT_COST).unwrap();
    conn.execute("insert into rustyauth.users (username, password, email, created_on) values($1, $2, $3, current_timestamp)", &[login, &hashed, &email]).unwrap();
}

fn verify_login(conn: &Connection, username: &String, password: &String) -> bool {
    let rows = &conn
        .query(
            "select password from rustyauth.users where username = $1",
            &[&username],
        )
        .unwrap();
    if rows.len() == 1 {
        let row_password: String = rows.get(0).get(0);
        let valid = verify(password, &row_password).unwrap();
        if valid {
            // update time of last login
            conn.execute(
                "update rustyauth.users set last_login=current_timestamp where username=$1",
                &[&username],
            )
            .unwrap();
            true
        } else {
            // verify(password, &"".to_string()).unwrap();  // consume the same time to mitigate timing attacks
            false
        }
    } else {
        // verify(password, &"".to_string()).unwrap();  // consume the same time to mitigate timing attacks
        false
    }
}

fn verify_client(conn: &Connection, client_id: &String, client_secret: &String) -> bool {
    let rows = &conn
        .query(
            "select client_secret from rustyauth.clients where client_id = $1",
            &[&client_id],
        )
        .unwrap();
    if rows.len() == 1 {
        let row_password: String = rows.get(0).get(0);
        let valid = verify(client_secret, &row_password).unwrap();
        if valid {
            // update time of last login
            // conn.execute("update rustyauth.clients set last_login=current_timestamp where username=$1", &[&username]).unwrap();
            true
        } else {
            // verify(password, &"".to_string()).unwrap();  // consume the same time to mitigate timing attacks
            false
        }
    } else {
        // verify(password, &"".to_string()).unwrap();  // consume the same time to mitigate timing attacks
        false
    }
}

fn verify_code_for_client(
    conn: &Connection,
    client_id: &String,
    code: &String,
    redirect_uri: &String,
) -> bool {
    let clients = &conn
        .query(
            "select url from rustyauth.clients where client_id=$1",
            &[client_id],
        )
        .unwrap();
    if clients.len() == 1 {
        let client_url: String = clients.get(0).get(0);
        // validate proper redirect url and prevent code/hijacking attempts
        if redirect_uri.contains(&client_url) {
            let rows = &conn
                .query(
                    "select code from rustyauth.client_code where client_id=$1 and code=$2;",
                    &[client_id, code],
                )
                .unwrap();
            if rows.len() == 1 {
                // cleanup, its a one-time code:
                &conn
                    .execute(
                        "delete from rustyauth.client_code where client_id=$1 and code=$2",
                        &[client_id, code],
                    )
                    .unwrap();
                return true;
            }
        }
    }
    false
}
