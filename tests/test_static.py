
import rethinkdb as ret
admin_password = '32d10aa2-13d9-593d-9f4b-ccc871d493b5'
admin_mnemonic = "laugh crumble meat good call muffin spare gather home clog attend clever wait deliver clinic vivid alcohol bottom elder into mosquito sock wealth violin"


admin_data =  {'master_private_key': '7ae0966ecc6d93054c21cf63c3467f83c320bc5dc83c6ac9d3f0454ee7043a7f',
  'master_public_key': '02b81c0171bff9149987d139ef1ab80b5219cbb6020ac3b0a9b51fffd2163fc9aa',
  'mnemonic': 'laugh crumble meat good call muffin spare gather home clog attend clever wait deliver clinic vivid alcohol bottom elder into mosquito sock wealth violin',
  'zeroth_private_key': 'e95e5224f452c3d1d5c27049e8afe7dca78e375cb62295f2356d7633903852bb',
  'zeroth_public_key': '0344d1d94f6cb733d83b50d89d162596b13beecba4102ce5519b28d57ef5a1a3b8'}

user1 = {'first_name': 'Saurav',
 'last_name': 'Verma',
 'email': 'houzier.saurav@gmail.com',
 'phone_number': '9315048070',
 'password': '84Ll*qtG)p',
 'pancard': '978-1-949144-33-8',
 'new_password': 'PA#DDEdQ@2'}


user2 = {'first_name': 'William',
 'last_name': 'Williams',
 'email': 'riveraemily@hotmail.com',
 'phone_number': '(105)727-4344x68604',
 'password': 'vn&0(IvCC5',
 'pancard': '978-0-913240-89-2'}


user3 = {'first_name': 'Anthony',
 'last_name': 'Lane',
 'email': 'jacqueline64@newman-owens.com',
 'phone_number': '1-766-605-2710',
 'password': '$*8sN9HmBb',
 'pancard': '978-0-595-38708-3'}


user4 = {'first_name': 'Timothy',
 'last_name': 'Clements',
 'email': 'zlawson@hotmail.com',
 'phone_number': '07660888410',
 'password': '+9X(uoa*4F',
 'pancard': '978-0-10-924098-9'}



user5 = {'first_name': 'Carrie',
 'last_name': 'Moore',
 'email': 'joseph13@gmail.com',
 'phone_number': '+75(3)5180807914',
 'password': '@*SHN%t8#1',
 'pancard': '978-1-71835-530-9'}


user6 = {'first_name': 'Sarah',
 'last_name': 'Munoz',
 'email': 'rebeccalucas@gmail.com',
 'phone_number': '855-470-3280x85780',
 'password': 'rPO+k^5u+6',
 'pancard': '978-1-4236-4283-1'}

#----------------------------APIS -------------------------------------------##

DATABASE={
            "ip":"13.233.46.185",
            "port": 28015,
            "dbname": "remediumdb",
            "user": "remedium",
            "password": "CLOCK768WORK768orange768@@",
            "user_table": "users",
            "public_keys_table": "public_keys"
              }

conn = ret.connect(
        port=DATABASE["port"],
        host=DATABASE["ip"],
        db=DATABASE["dbname"],
        user=DATABASE["user"],
        password=DATABASE["password"])

admin = {"email": "admin@qcin.org", "password": "1234", "org_name": "Quality council of India"}

REST_API_URL = "http://localhost:8000"
USER_REGISTRATION = f"{REST_API_URL}/accounts/users/registration"


SHARE_MNEMONIC = f"{REST_API_URL}/accounts/users/share_mnemonic"
LOGIN = f"{REST_API_URL}/accounts/login"
GET_OTPS = f"{REST_API_URL}/accounts/users/get_otps"

FORGOT_PASSWORD = f"{REST_API_URL}/accounts/users/forgot_password"
ALL_SHARE_SECRETS = f"{REST_API_URL}/accounts/users/all_share_secrets"
EXECUTE_SHARE_SECRET = f"{REST_API_URL}/accounts/users/execute_shared_secret"
CREATE_RECEIVE_SECRET = f"{REST_API_URL}/accounts/users/create_receive_secret"
