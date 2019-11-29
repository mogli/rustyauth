FROM rust:1.39-stretch AS rustyauth

WORKDIR /usr/src/rustyauth

ADD Cargo.toml .
ADD src/ src/

RUN cargo install --path .

#ADD Cargo.toml /rustyauth/
#ADD src/ /rustyauth/src/

RUN apt update && apt install -y postgresql postgresql-contrib

#RUN cd /rustyauth && \
#    cargo build --release

#RUN ls -lah  /rustyauth/target/release | grep rustyauth

# ----------------------------

#FROM postgres:12.1-alpine

#COPY --from=rustyauth /rustyauth/target/release/rustyauth /rustyauth

#RUN apk update && apk upgrade


# USER oauth2
#RUN chmod a+x /rustyauth

RUN echo "listen_addresses = '*'" >> /etc/postgresql/9.6/main/postgresql.conf &&\
    service postgresql start &&\
    su -c 'psql --command="create database oauth2;"' postgres

RUN apt install nano

#RUN groupadd -g 999 oauth2 && \
#    useradd -r -u 999 -g oauth2
EXPOSE 8000/tcp
USER postgres
CMD ["service postgresql start && rustyauth"]
