FROM rust as builder
RUN apt-get update
RUN apt install -y libssl-dev
RUN apt install -y clang llvm-dev libclang-dev

COPY ./src /home/src/
COPY ./Cargo.toml ./home/Cargo.toml
COPY ./.env /home/.env
COPY ./key.pem /home/key.pem
COPY ./cert.pem /home/cert.pem
EXPOSE 8080

WORKDIR /home/
RUN cargo build --release
RUN  cp ./target/release/yolo_users /bin/yolo_users

FROM ubuntu
RUN apt-get update
RUN apt install -y libssl-dev
RUN apt install -y clang llvm-dev libclang-dev
COPY --from=builder --chown=1:1 ${HOME}/bin/yolo_users  /app/main
COPY --from=builder --chown=1:1 /home/key.pem app/key.pem
COPY --from=builder --chown=1:1 /home/cert.pem app/cert.pem
COPY --from=builder --chown=1:1 /home/.env app/.env
EXPOSE 8080
WORKDIR /app
USER 1000
CMD [ "./main" ]
