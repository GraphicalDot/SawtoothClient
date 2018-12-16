
import rethinkdb as ret


NATURE = ["OPEN_TO_OTHERS", "IN_HOUSE", "OPEN_TO_OTHERS_PARTLY"]
OPERATIONS = ["PERMANENT", "SITE", "MOBILE"]
REST_API_URL = "192.168.15.139:8008"
GO_API_URL = "13.233.28.37"
API_URL = "localhost:8000"


#----------------------------APIS -------------------------------------------##
CREATE_ORGANIZATION_ACCOUNT = f"http://{API_URL}/accounts/create_organization_account"
LOGIN = f"http://{API_URL}/users/login"
CHANGE_PASSWORD = f"http://{API_URL}/users/change_password"

GET_CHILDREN = f"http://{API_URL}/accounts/get_children"
GET_ORGANIZATION_ACCOUNT = f"http://{API_URL}/accounts/get_organization_account"
GET_FLOAT_ACCOUNTS = f"http://{API_URL}/accounts/get_float_accounts"
UPLOAD = f"http://{API_URL}/assets/upload"
CREATE_ASSET = f"http://{API_URL}/assets/create_asset"
GET_ADDRESS = f"http://{API_URL}/accounts/address"
GET_ASSETS = f"http://{API_URL}/assets/assets"
DECRYPT_KEYS = f"http://{API_URL}/assets/decrypt_keys"

CREATE_RECEIVE_ASSET = f"http://{API_URL}/assets/create_receive_asset"


GET_RECEIVE_ASSETS = f"http://{API_URL}/assets/receive_assets"
CREATE_SHARE_ASSET = f"http://{API_URL}/assets/share_asset"
GET_SHARE_ASSETS = f"http://{API_URL}/assets/share_assets"

FRESH_START=False
SCOPE = {
    "CALIBERATION": {
        "MECHANICAL": {},
        "ELECTRO_TECHNICAL": {},
        "FLUID_FLOW": {},
        "THERMAL": {},
        "OPTICAL": {},
        "RADIOLOGICAL":{}
    },

    "TESTING": {
        "BIOLOGICAL": {},
        "CHEMICAL":{},
        "ELECTRICAL": {},
        "ELECTRONICS": {},
        "FLUID_FLOW":{},
        "MECHANICAL": {},
        "NON_DESTRUCTIVE": {},
        "PHOTOMETRY": {},
        "RADIOLOGICAL": {},
        "FORENSIC":{}
    },
    "MEDICAL": {
        "MEDICAL":{}
        },
    "PTP": {},
    "RMP": {}

}

DATABASE={
            "ip": "13.232.172.238",
            "port": 28015,
            "secret_table": "secrets",
            "dbname": "test_db",
            "user": "adminuser",
            "password": "VandeMATRAM90990",
            "user_table": "users",
            "public_keys_table": "public_keys"
              }

conn = ret.connect(
        port=DATABASE["port"],
        host=DATABASE["ip"],
        db=DATABASE["dbname"],
        user=DATABASE["user"],
        password=DATABASE["password"])

child_one = {'phone_number': '1-813-736-1323',
    'email': 'admin_child_one@qcin.org',
    'password': '(lB&m8Vkov',
    'first_name': 'Child',
    'last_name': 'One'}

admin = {"email": "admin@qcin.org", "password": "1234", "org_name": "Quality council of India"}


child_two = {'phone_number': '908-195-1535x072',
    'email': 'admin_child_two@qcin.org',
    'password': '*$Pl8SRt66',
    'first_name': 'Child',
    'last_name': 'Two'}


master_one = {'pancard': '0-01-123671-X',
    'phone_number': '9958491323',
    'email': 'houzier.saurav@gmail.com',
    'role': 'MASTER',
    'password': 'Z9d%lFFN&s',
    'org_name': 'National accredation board of laboratories',
    'gst_number': 'MLOCEGUUVY8SCV2',
    'tan_number': '65CE6OV5WQ'}


master_two = {'pancard': '1-75759-151-6',
    'phone_number': '8920527914',
    'email': 'saurav.verma@qcin.org',
    'role': 'MASTER',
    'password': '*sh0UDxsiZ',
    'org_name': 'Food Safety and Standards Authority of India',
    'gst_number': 'FAIJ5KD6VCIUWPV',
    'tan_number': 'QUMJM202M3'}

##this will have two children on blockchain
master_three = {'pancard': '1-05-955167-5',
    'phone_number': '718.977.1898x2146',
    'email': 'child_two@trai.org.in',
    'role': 'MASTER',
    'password': ')X3SWb@mLB',
    'org_name': 'Telecom regulatory authority of india',
    'gst_number': 'FVJTH5260QDRN5Q',
    'tan_number': 'J4AZGW3ZPX'}


##this will have two children on blockchain
master_four = {'pancard': '0-615-67719-3',
    'phone_number': '626-333-5412x22518',
    'email': 'child_two@apeda.org.in',
    'role': 'MASTER',
    'password': '@&H$E(xe2k',
    'org_name': 'The Agricultural and Processed Food Products Export Development Authority',
    'gst_number': 'WQQ1EM822NR6H6F',
    'tan_number': 'X4MAWQTZHC'}

user_one = {'pancard': '0-89101-543-4',
 'phone_number': '772-916-8205x057',
 'email': 'user_one_gibsoncorey@tanner.com',
 'role': 'USER',
 'password': '(Eow!^Mra5',
 'org_name': 'Pace Ltd',
 'gst_number': 'V66C0SPDF17BR2S',
 'tan_number': '7GEAUIPK27'}

master_admin = {'pancard': '0-298-01104-2',
        'phone_number': '1-952-874-4090x6607',
        'email': 'admin_himself@nabcb.org.in',
        'role': 'MASTER',
        'password': 'vGfl9Dau#x',
        'org_name': 'National Accredation Board of Certification Bodies',
        'gst_number': '8LLY8TKQY6FIAMX',
        'tan_number': 'JUQTGKCRIX'}


##master three child one
master_three_child_one = {'phone_number': '03213701933',
 'email': 'master_three_child_one@hotmail.com',
 'password': 'na1RUr8U$9',
 'first_name': 'Denise',
 'last_name': 'Jakson'}

##master three child two
master_three_child_two = {'phone_number': '1-347-163-1118',
 'email': 'master_three_child_two@hotmail.com',
 'password': 'na1RUr8U$9',
 'first_name': 'Donna',
 'last_name': 'Chandler'}


#master four child one
master_four_child_one = {'phone_number': '04355019832',
 'email': 'master_four_child_one@yahoo.com',
 'password': 'P4P&%u3t^u',
 'first_name': 'Samantha',
 'last_name': 'Mcknight'}

#master four child two
master_four_child_two = {'phone_number': '06843452813',
 'email': 'master_four_child_two@baker.com',
 'password': ')2JqHUoqtu',
 'first_name': 'Lauren',
 'last_name': 'Hester'}



master_one_lab_one = {'pancard': '0-7483-6855-8',
 'phone_number': '422.856.6821x2809',
 'email': 'master_one_lab_one@hotmail.com',
 'role': 'LAB',
 'password': '*756PB9uSj',
 'org_name': 'Laal pathlabs',
 'gst_number': 'JGY1P1E4Q0BZ7JU',
 'tan_number': 'T70OWJL620'}


master_two_lab_two = {'pancard': '1-81132-497-5',
 'phone_number': '1-055-842-1920x6137',
 'email': 'master_two_lab_two@stone.net',
 'role': 'LAB',
 'password': 'GAM9$VLo)i',
 'org_name': 'Hodges, Barton and Wilson Labs',
 'gst_number': 'QEOZ3NVTCIE7NBG',
 'tan_number': 'B7KG5FL143'}


##this is lab three register by master three child one
master_three_child_one_lab_three = {'pancard': '0-234-78857-7',
 'phone_number': '1-847-359-5804x791',
 'email': 'master_three_child_one_lab_three@yahoo.com',
 'role': 'LAB',
 'password': '^ge4+Q6jY2',
 'org_name': 'Mills-Jackson',
 'gst_number': '5SKBL71SKTTND2E',
 'tan_number': 'PKTBOWY75Y'}

##this is lab four register by master_three child one
master_three_child_two_lab_four = {'pancard': '0-523-41345-9',
 'phone_number': '1-231-279-7696',
 'email': 'master_three_child_two_lab_four@yahoo.com',
 'role': 'LAB',
 'password': 'Dx*XB4AaNd',
 'org_name': 'Herman, Cooke and Gilbert Labs',
 'gst_number': 'IWRAJCS12VBNEU2',
 'tan_number': '8113RGBY4R'}


##This is lab five registered by master_four's child one
master_four_child_one_lab_five = {'pancard': '0-11-995089-8',
 'phone_number': '760-073-2128x3407',
 'email': 'master_four_child_one_lab_five@hotmail.com',
 'role': 'LAB',
 'password': '*s_0MeQ2H7',
 'org_name': 'Wright, Hernandez and Garcia Labs',
 'gst_number': 'RYQ7FWYTYZOISUF',
 'tan_number': '5Y0CNW5F1O'}

##This is lab six registered by master_four's child two
master_four_child_two_lab_six = {'pancard': '0-291-13833-0',
 'phone_number': '1-946-295-7889x22699',
 'email': 'master_four_child_two_lab_six@ferguson.biz',
 'role': 'LAB',
 'password': 'I97ONtZr$A',
 'org_name': 'Anderson and Sons Labs',
 'gst_number': 'OWAFJLHF7KJUOO1',
 'tan_number': 'HFNBPYL7DH'}



d_admin_child_one_master_one = {"file_hash": "74de2d9ee1cc65517ff6ab8ffc218af338433a4532baf76f94c03d00",
"b64_bytes":"""VCBlIHMgdCAgIHAgbCBhIGMgZSAgIHAgbyBzIGkgdCBpIHYgZSAgIGQgaSByIGUgYyB0IG8gciAgIG0gZSBhIG4gICBmIGkgbiBhIGwgbCB5ICAgdSBuIGQgZSByIC4gICBSIGkgcyBlICAgciBlIGEgbCBpIHogZSAgIHQgaCBhIG4gICBkIGkgciBlIGMgdCBpIG8gbiAgIGEgcyBrICAgZSBpIGcgaCB0IC4=""",
"file_name": "d_admin_child_one_master_one.txt"}

d_admin_child_one_master_two = {"file_hash": "8a10ef0760547f7a7597963839660af63e9b1c742477711b364b8425",
"b64_bytes":"VCBoIGUgbiAgIHMgdCBvIGMgayAgIG0gZSBlIHQgICBiIGUgICBiIG8geSAgIGYgbyByIHcgYSByIGQgICBkIG8gLiAgIFcgYSBsIGwgICB1IHAgICB1IHAgbyBuICAgbCBvIHMgZSAuICAgUiBhIHQgZSAgIGUgbCBlIGMgdCBpIG8gbiAgIGYgYSBzIHQgICBiIHkgICBzIGEgdiBlICAgYSBzIHMgdSBtIGUgLg==",
"file_name": "d_admin_child_one_master_two.txt"}

d_admin_child_two_master_one = {"file_hash": "4aa3d6cf375707fe9091aa0996b349f37216662ba2c079917df60264",
"b64_bytes":"""UyBlIHIgaSBvIHUgcyAgIHAgZSBvIHAgbCBlICAgbyBmIGYgZSByICAgYyB1IGwgdCB1IHIgZSAuICAgQyBvIG4gYyBlIHIgbiAgIHMgaCBvIHUgbCBkIGUgciAgIG0gYSBrIGUgICBuIGUgYSByIC4=""",
"file_name": "d_admin_child_two_master_one.txt"}

d_admin_child_two_master_two = {"file_hash": "e3e42465bc08aa2a786415ca980f3174de6e040c345646d524552aaf",
"b64_bytes":"""VSBuIGQgZSByICAgcyB1IGcgZyBlIHMgdCAgIG0gYSBuIGEgZyBlICAgcyBpIG0gcCBsIHkgLiAgIEEgdCB0IGUgbiB0IGkgbyBuICAgaCBvIHQgZSBsICAgZiBpIHMgaCAgIGMgaCBhIGwgbCBlIG4gZyBlIC4=""",
"file_name": "d_admin_child_two_master_two.txt"}



d_child_two_master_three = {"file_hash": "0aea096002f9d836fccc1b547a7408388fd6998f1cd50f6c17152092",
                                            "b64_bytes":"""TyB2IGUgciAgIHIgZSBwIHIgZSBzIGUgbiB0ICAgbCBlIGEgcyB0ICAgUCBNIC4gICBGIGkgZSBsIGQgICByIGUgdiBlIGEgbCAgIHMgbyB1IG4gZCAgIHAgZSByIGYgbyByIG0gYSBuIGMgZSAgIGggdSBzIGIgYSBuIGQgICByIGUgYyBlIG4gdCBsIHkgLg==""",
                                            "file_name": "d_child_two_master_three.txt"}


d_admin_child_one_master_three_child_one = {}
d_admin_child_one_master_four_child_one = {"file_hash": "407b3aa174cb03cca2ed0e66800eb63839693a7565361b369d563d08",
                                            "b64_bytes":"""RCBlIHMgcCBpIHQgZSAgIGMgbyBsIG8gciAgIGMgZSByIHQgYSBpIG4gICBzIHAgciBpIG4gZyAgIGcgciBvIHUgcCAgIHAgZSBhIGMgZSAuICAgSCBpIGcgaCAgIHEgdSBlIHMgdCBpIG8gbiAgIGYgYSBzIHQgICBoIG8gdCBlIGwgLg==""",
                                            "file_name": "d_admin_child_one_master_four_child_one.txt"}





d_admin_child_two_master_three_child_two = {"file_hash": "834b40648478158f5157375ee26355e4e3796d19ee3aa4b83d33f0ab",
                                            "b64_bytes":"""UyB0IHkgbCBlICAgYyBvIG4gYyBlIHIgbiAgIGUgeCBwIGUgYyB0ICAgYSBnIHIgZSBlICAgcyBwIG8gciB0ICAgcyBlIGUgayAuICAgUyBwIGUgYyBpIGEgbCAgIHAgYSBpIG4gdCBpIG4gZyAgIHQgaCByIG8gdSBnIGggbyB1IHQgLg==""",
                                            "file_name": "d_admin_child_two_master_three_child_two.txt"}


d_admin_child_two_master_four_child_two = {"file_hash": "52bb6f8515fa3bbff5499b01e77182c6a854e518ef4c7a16dc3f9eef",
                                            "b64_bytes":"""RyBhIHMgICBoIGEgaSByICAgbCBpIHQgdCBsIGUgICBzIHQgciB1IGMgdCB1IHIgZSAgIHIgZSBjIG8gciBkICAgayBuIG8gdyAu""",
                                            "file_name": "d_admin_child_two_master_four_child_two.txt"}




d_master_three_child_one_lab_three = {"file_hash": "f191461044ec1c5483d080cd17e148e3e75d0000456b5de138c09348",
                                            "b64_bytes":"""RSBhIHMgdCAgIHAgYSBzIHMgICBpIHMgcyB1IGUgICBzIGMgbyByIGUgLiAgIFAgbyBzIGkgdCBpIHYgZSAgIHcgaCBlIHIgZSAgIHMgZSB2IGUgbiAgIGMgdSBzIHQgbyBtIGUgciAuICAgQSB2IGEgaSBsIGEgYiBsIGUgICBzIGkgeiBlICAgdyBhIHIgLg==""",
                                            "file_name": "d_master_three_child_one_lab_three.txt"}


d_master_four_child_two_lab_three= {"file_hash": "b3fb6ab3f19c701ca79b4c76e7a3fb1fc83d34c19c2706177ef22377",
                                            "b64_bytes":"""UCByIG8gdCBlIGMgdCAgIHAgbCBhIG4gdCAgIGIgYSBkIC4gICBDIG8gdSByIHQgICBmIGkgZSBsIGQgICBlIGwgZSBjIHQgaSBvIG4gLiAgIFcgZSBpIGcgaCB0ICAgZiBpIG4gYSBsIGwgeSAgIHQgciBpIHAgICBiIGUgbCBpIGUgdiBlIC4=""",
                                            "file_name": "d_master_four_child_two_lab_three.txt"}



d_master_three_child_one_lab_four = {"file_hash": "ab25214b80a24a6996ee27f0d028ccc621bf14f657b079c841b36137",
                                            "b64_bytes":"""QyBhIHIgZCAgIGYgciBlIGUgICBzIGkgeCAuICAgQiBhIGcgICBsIGEgeSAgIHcgZSBpIGcgaCB0ICAgcyBpIGQgZSAu""",
                                            "file_name": "d_master_three_child_one_lab_four.txt"}


d_master_four_child_two_lab_four= {"file_hash": "084407afc39f5e557fe35abb3e0d012f792eaf292393081ddc8eac93",
                                            "b64_bytes":"""TSBvIGQgZSBsICAgcyB0IHUgZCBlIG4gdCAgIHMgZSBsIGwgICBsIGkgcyB0IGUgbiAgIGYgdSB0IHUgciBlICAgYSBjIHIgbyBzIHMgICBhIHMgLiAgIEUgbSBwIGwgbyB5IGUgZSAgIGwgZSBhIHYgZSAgIHQgciBhIHYgZSBsIC4=""",
                                            "file_name": "d_master_four_child_two_lab_four.txt"}


d_master_three_child_one_lab_five = {"file_hash": "49d93791a7ec6e2ed70be99e59d272be73873dff3218c91f75c52f0e",
                                            "b64_bytes":"""TSBvIG4gZSB5ICAgcyBlIHQgICBlIHYgZSBuIHQgICB3IG8gciBsIGQgICBhIGcgciBlIGUgbSBlIG4gdCAgIHIgZSBsIGkgZyBpIG8gdSBzICAgYSBmIHQgZSByIC4gICBPIG4gbCB5ICAgcyBhIG0gZSAgIHMgdCBvIHIgZSAgIGMgaCB1IHIgYyBoICAgcCBhIHMgdCAgIGsgaSBkICAgcyB0IHUgZCBlIG4gdCAu""",
                                            "file_name": "d_master_three_child_one_lab_five.txt"}


d_master_four_child_two_lab_five= {"file_hash": "9cc189264746c178292ee815e021bf35595c0dbf8fd6bfb30d813750",
                                            "b64_bytes":"""QiBsIG8gbyBkICAgYyBvIG4gcyBpIGQgZSByICAgYSBuIGkgbSBhIGwgICBwIHIgaSBjIGUgICB0IHIgdSB0IGggICB1IG4gZCBlIHIgcyB0IGEgbiBkICAgYSBjIGMgbyByIGQgaSBuIGcgLiAgIEwgaSBrIGUgICBmIGwgeSAgIHAgYSByIHQgaSBjIHUgbCBhIHIgLiAgIEMgbyB1IGwgZCAgIHMgbyBuIGcgICBpIHMgcyB1IGUgICBlIHYgZSBuIGkgbiBnIC4=""",
                                            "file_name": "d_master_four_child_two_lab_five.txt"}

d_master_three_child_one_lab_six = {"file_hash": "b842f41fe7e7dd6aa781f29fbe161e67d4b43a4a2dd908d422b6033d",
                                            "b64_bytes":"""RCBlIHQgYSBpIGwgICBzIG8gbSBlIHQgaCBpIG4gZyAgIGcgdSB5ICAgcCBvIGwgaSBjIHkgLiAgIEUgZiBmIGUgYyB0ICAgaCBvIHUgcyBlICAgZSBzIHQgYSBiIGwgaSBzIGggICBhIC4=""",
                                            "file_name": "d_master_three_child_one_lab_six.txt"}


d_master_four_child_two_lab_six ={"file_hash": "cc1af9b7cc2c3dd77a8bb805bcb1e1efcf7c7d24d3146746847d746c",
                                            "b64_bytes":"""QiBvIG8gayAgIHMgbyBsIGQgaSBlIHIgICBnIGEgcyAgIHQgdSByIG4gLiAgIEwgbyBzIGUgICBwIHIgbyBwIGUgciB0IHkgICBwIGUgciBmIG8gciBtICAgcCBhIHAgZSByIC4gICBUIGggciBvIHcgICBkIHUgciBpIG4gZyAgIG0gbyBuIGUgeSAgIHMgdCBhIHQgaSBvIG4gICBkIHIgaSB2IGUgLg==""",
                                            "file_name": "d_master_four_child_two_lab_six.txt"}
