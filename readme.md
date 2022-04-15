run the app:

    docker-compose up -d


execute the migration: (1 time)

    sqlx mig run (it will use the .env file for database url)

start psql server:
    sudo systemctl start postgresql
    -see status : systemctl status postgresql.service

    connect: sudo su - postgres
             psql

florian/yoann = azertyuiop

token maybe expire


test /me :

curl --request GET --url http://localhost:4201/me --header 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJmN2E5MDhiZi05M2NlLTRlNzctYWVhZS1kZDkyYmUyM2ZmYjQiLCJleHAiOjE2NDE1NjQzMDl9.6s2MA9tnL54xWYnneJ_6reWBBBBmmAoX__vkTt4XkJo'


si sqlx ne veut pas mig run -> drop table _sqlxmigration dans psql 


prendre un cookie dans un req : Httprequest type
request.cookie("JWT").unwrap().value()




git :
    git add .
    git commit -m ""
    git push -f --set-upstream https://github.com/eridio/yolo_address_book master
    
    
    https://aralroca.com/blog/first-steps-webassembly-rust