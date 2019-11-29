use postgres::Connection;

pub fn init_database_schema(conn: &Connection) {
    conn.execute("create schema rustyauth;", &[]).unwrap();
    conn.execute("create table rustyauth.user_role( user_id integer not null, role_id integer not null, grant_date timestamp without time zone );", &[]).unwrap();
    conn.execute("create table rustyauth.role ( role_id serial primary key, role_name varchar(255) unique not null);", &[]).unwrap();
    conn.execute("create table rustyauth.users ( user_id serial primary key, username varchar(255) unique not null, password varchar(4096) not null, email varchar (500) unique not null, created_on timestamp not null, last_login timestamp );", &[]).unwrap();
    conn.execute("create table rustyauth.clients ( client_id char(36) primary key, client_name varchar(255) unique not null, client_secret varchar(4096) not null, url varchar(4096) not null, created_on timestamp not null, last_login timestamp );", &[]).unwrap();
    conn.execute("create table rustyauth.client_code ( client_id char(36) not null, user_id integer not null, code char(36) not null, scopes varchar, created_on timestamp not null );", &[]).unwrap();
}
