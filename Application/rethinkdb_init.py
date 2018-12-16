
admin_password ="32d10aa2-13d9-593d-9f4b-ccc871d493b5"

##to run rethinkdb with password from command line
##sudo rethinkdb -d rethinkdb_data_dir  --bind-http 0.0.0.0 --bind all --initial-password 32d10aa2-13d9-593d-9f4b-ccc871d493b5

ret.connect('172.28.128.3', 28015, password=admin_password).repl()
list(ret.db('rethinkdb').table('server_status').run())


##Create new user
ret.db('rethinkdb').table('users').insert({"id": "remedium", "password": "CLOCK768WORK768orange768@@"}).run()

##update rethinkdb user password
r.db('rethinkdb').table('users').get('bob').update({password: false})


#new database
#ret.db_create("remediumdb").run()

##to grant new user remedium rights on new databse remediumdb
##ret.db("remediumdb").grant('remedium', {"read": True, "write": True, "config": False}).run()


##since the user remedium dosent have config permission on remediumdb
##the new tables must be created by admi user like this

for table in ["transfer_assets", "assets", "share_assets", "users"]:
    ret.db('remediumdb').table_create(table).run()
