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

// BEGIN: database model
struct Client {
    client_id: String,
    client_name: String,
    client_secret: String,
    url: String,
}

struct User {
    user_id: i32,
    username: String,
    password: String,
    email: String,
}

trait LoadStoreClient {
    fn store_client(&self, c: &Client);
    fn load_client(&self, client_id: String) -> Option<Client>;

    fn store_client_code(&self, client_id: &String, user_id: i32, code: &String, scopes: &String);
    fn has_client_code(&self, client_id: &String, code: &String) -> bool;
    fn login_client(&self, client_id: &String);
    fn delete_client_code(&self, client_id: &String, code: &String);

    fn store_user(&self, u: &User);
    fn load_user(&self, username: &String) -> Option<User>;
    fn login_user(&self, username: &String);

    fn drop_schema(&self);
    fn init_db_schema(&self);
}

struct PostgresClient {
    c: Connection,
}

impl LoadStoreClient for PostgresClient {
    fn store_client(&self, c: &Client) {
        self.c.execute("insert into rustyauth.clients (client_id, client_name, client_secret, url, created_on) values ($1, $2, $3, $4, current_timestamp);",
            &[&c.client_id, &c.client_name, &c.client_secret, &c.url]).unwrap();
    }

    fn load_client(&self, client_id: String) -> Option<Client> {
        let rows = &self.c
        .query(
            "select client_name, client_secret, url from rustyauth.clients where client_id = $1",
            &[&client_id],
        )
        .unwrap();
        if rows.len() == 1 {
            let r = rows.get(0);
            return Some(Client {
                client_id: client_id.clone(),
                client_name: r.get(0),
                client_secret: r.get(1),
                url: r.get(2),
            });
        }
        None
    }

    fn store_client_code(&self, client_id: &String, user_id: i32, code: &String, scopes: &String) {
        self.c.execute("insert into rustyauth.client_code (client_id, user_id, code, scopes, created_on) values ($1, $2, $3, $4, current_timestamp);", &[client_id, &user_id, &code, &scopes]).unwrap();
    }

    fn has_client_code(&self, client_id: &String, code: &String) -> bool {
        let rows = &self
            .c
            .query(
                "select code from rustyauth.client_code where client_id=$1 and code=$2;",
                &[client_id, code],
            )
            .unwrap();
        if rows.len() == 1 {
            return true;
        }
        false
    }


    fn login_client(&self, client_id: &String) {
        self.c
            .execute(
                "update rustyauth.clients set last_login=current_timestamp where client_id=$1",
                &[client_id],
            )
            .unwrap();
    }

    fn delete_client_code(&self, client_id: &String, code: &String) {
        self.c
            .execute(
                "delete from rustyauth.client_code where client_id=$1 and code=$2",
                &[client_id, code],
            )
            .unwrap();
    }

    fn store_user(&self, u: &User) {
        self.c.execute("insert into rustyauth.users (username, password, email, created_on) values($1, $2, $3, current_timestamp)",
        &[&u.username, &u.password, &u.email]).unwrap();
    }

    fn load_user(&self, username: &String) -> Option<User> {
        let rows = &self
            .c
            .query(
                "select user_id, password, email from rustyauth.users where username = $1",
                &[username],
            )
            .unwrap();
        if rows.len() == 1 {
            return Some(User {
                user_id: rows.get(0).get(0),
                username: username.clone(),
                password: rows.get(0).get(1),
                email: rows.get(0).get(2),
            });
        }
        None
    }

    fn login_user(&self, username: &String) {
        self.c
            .execute(
                "update rustyauth.users set last_login=current_timestamp where username=$1",
                &[username],
            )
            .unwrap();
    }

    fn drop_schema(&self) {
        self.c
            .execute("drop schema if exists rustyauth cascade;", &[])
            .unwrap();
    }

    fn init_db_schema(&self) {
        let t = self.c.transaction().unwrap();
        t.execute("create schema rustyauth;", &[]).unwrap();
        t.execute("create table rustyauth.user_role( user_id integer not null, role_id integer not null, grant_date timestamp without time zone );", &[]).unwrap();
        t.execute("create table rustyauth.role ( role_id serial primary key, role_name varchar(255) unique not null);", &[]).unwrap();
        t.execute("create table rustyauth.users ( user_id serial primary key, username varchar(255) unique not null, password varchar(4096) not null, email varchar (500) unique not null, created_on timestamp not null, last_login timestamp );", &[]).unwrap();
        t.execute("create table rustyauth.clients ( client_id char(36) primary key, client_name varchar(255) unique not null, client_secret varchar(4096) not null, url varchar(4096) not null, created_on timestamp not null, last_login timestamp );", &[]).unwrap();
        t.execute("create table rustyauth.client_code ( client_id char(36) not null, user_id integer not null, code char(36) not null, scopes varchar, created_on timestamp not null );", &[]).unwrap();
        t.commit().unwrap();
    }
}
// END: database model

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
        let db_client = PostgresClient {
            c: Connection::connect(db_uri.clone(), TlsMode::None).unwrap(),
        };

        println!("- Initializing database schema.");
        if matches.is_present("cleanup") {
            println!("- Dropping existing schema.");
            db_client.drop_schema();
        }
        db_client.init_db_schema();

        let pw: String = thread_rng().sample_iter(&Alphanumeric).take(30).collect();
        adduser(
            &db_client,
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
    let db_client = PostgresClient {
        c: Connection::connect(db_uri.clone(), TlsMode::None).unwrap(),
    };
    router!(request,
        (POST) (/login) => {
            let data = try_or_400!(post_input!(request,{
                login: String,
                password: String,
            }));
            println!("Login attempt with login {:?}", data.login);
            let valid_password = verify_login(&db_client, &data.login, &data.password);
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
                if verify_client(&db_client, &data.client_id, &data.client_secret) && verify_code_for_client(&db_client, &data.client_id, &data.code, &data.redirect_uri) {
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
    let db_client = PostgresClient {
        c: Connection::connect(db_uri.clone(), TlsMode::None).unwrap(),
    };
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
            // todo: check if user exists!
            adduser(&db_client, &data.login, &data.password, &data.email);
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
            let client = Client{ client_id: client_id.clone(), client_name: data.client_name.clone(), client_secret: hashed.clone(), url: data.url};
            db_client.store_client(&client);
            let html_response = format!("<p>Client successfully created.</p> <p>Client-id: {}</p><p>Client-secret: {}</p> <p><a href=\"/clients\">Client Manangement</a></p>", client_id, client_secret);
            Response::html(html_response)
        },
        (GET) (/oauth/authorize) => {
            let client_id: String = request.get_param("client_id").unwrap();
            let redirect_uri: String = request.get_param("redirect_uri").unwrap();
            let scopes: String = request.get_param("scope").unwrap();
            let code: String = generate_code(&db_client, &client_id, &_session_data.login, &redirect_uri, &scopes);
            let redirect: String = format!("{}?code={}", redirect_uri, code);
            Response::redirect_303(redirect)
        },
        _ => Response::empty_404()
    )
}

fn generate_code(
    db_client: &PostgresClient,
    client_id: &String,
    username: &String,
    redirect_uri: &String,
    scopes: &String,
) -> String {
    let user = db_client.load_user(username).unwrap();
    println!("Loading url for client {} and user {}", client_id, username);

    // check for existing client:
    let client = db_client.load_client(client_id.clone());
    match client {
        Some(client) => {
            if redirect_uri.contains(&client.url) {
                let code: String = uuid::Uuid::new_v4().to_string();
                db_client.store_client_code(client_id, user.user_id, &code, scopes);
                return code;
            } else {
                println!("urls mismatch");
            }
        }
        None => {
            println!("client {} not found", client_id);
        }
    }
    "".to_string()
}

fn adduser(db_client: &PostgresClient, login: &String, password: &String, email: &String) {
    let hashed = hash(password, DEFAULT_COST).unwrap();
    let u = User {
        user_id: 42, // will be generated
        username: login.clone(),
        password: hashed,
        email: email.clone(),
    };
    db_client.store_user(&u);
}

fn verify_login(db_client: &PostgresClient, username: &String, password: &String) -> bool {
    let some_user = db_client.load_user(username);
    if some_user.is_none() {
        return false;
    }
    let user = some_user.unwrap();
    let valid = verify(password, &user.password).unwrap();
    if valid {
        // update time of last login
        db_client.login_user(username);
        true
    } else {
        false
    }
}

fn verify_client(db_client: &PostgresClient, client_id: &String, client_secret: &String) -> bool {
    let client = db_client.load_client(client_id.clone());
    if client.is_none() {
        return false;
    }
    let valid = verify(client_secret, &client.unwrap().client_secret).unwrap();
    if valid {
        // update time of last login
        db_client.login_client(client_id);
        true
    } else {
        // verify(password, &"".to_string()).unwrap();  // consume the same time to mitigate timing attacks
        false
    }
}

fn verify_code_for_client(
    db_client: &PostgresClient,
    client_id: &String,
    code: &String,
    redirect_uri: &String,
) -> bool {
    let client = db_client.load_client(client_id.clone()).unwrap();
    // validate proper redirect url and prevent code/hijacking attempts
    if redirect_uri.contains(&client.url) {
        let code_valid = db_client.has_client_code(client_id, code);
        if code_valid {
            db_client.delete_client_code(client_id, code);
        }
        return code_valid;
    }
    false
}
