FROM gcc:latest

WORKDIR /app

COPY . .

RUN gcc main.c libs/sha256.c src/mysql.c src/handshake_manager.c -o main

CMD ["./main"]