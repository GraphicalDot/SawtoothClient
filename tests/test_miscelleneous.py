


from faker import Faker
import hashlib
import rethinkdb as ret
import pytz
import datetime
import random
from io import StringIO
faker = Faker()
from test_static import API_URL
from test_static import LOGIN
import requests
import json
import uuid
from test_static import SCOPE, NATURE, OPERATIONS
import coloredlogs, logging
coloredlogs.install()


def get_headers(email, password):
    r = requests.post(LOGIN,
                            data=json.dumps({"email": email,
                                "password": password}))
    if r.status_code == 200:
        return {"token": r.json()["authorization"]}
    else:
        logging.error(r.json())
        return False

def receive_asset_data():
    _id_ = uuid.uuid4().hex
    name = faker.sentence()
    at_which_asset_expires = revoke_time_stamp(days=1, minutes=0)
    description = faker.paragraph()
    return _id_, name, at_which_asset_expires, description

def revoke_time_stamp(days=0, hours=0, minutes=0):
        tz_kolkata = pytz.timezone('Asia/Kolkata')
        time_format = "%Y-%m-%d %H:%M:%S"
        naive_timestamp = datetime.datetime.now()
        aware_timestamp = tz_kolkata.localize(naive_timestamp)
        ##This actually creates a new instance od datetime with Days and hours
        _future = datetime.timedelta(days=days, hours=hours, minutes=minutes)
        result = aware_timestamp + _future
        return result.timestamp()

def generate_file_like(number_of_sentences):
        output = StringIO()
        text = []
        for i in range(number_of_sentences):
            text.extend(faker.paragraphs())
        text = " ".join(text)
        output.write(text)
        content = output.getvalue()
        file_hash = hashlib.sha224(content.encode()).hexdigest()
        base64_file_bytes = base64.b64encode(content.encode()).decode()
        return file_hash, base64_file_bytes, faker.file_name()

def gen_gst_number():
    return "".join([random.choice([str(i) for i in range(0, 9)] + [chr(i) for i in range(97, 123)]) for i in range(0, 15)]).upper()

def gen_tan_number():
    return "".join([random.choice([str(i) for i in range(0, 9)] + [chr(i) for i in range(97, 123)]) for i in range(0, 10)]).upper()


def create_scope():

    group = random.choice(list(SCOPE.keys()))
    if len(SCOPE[group].keys()) > 2:
       sub_group = random.choice(list(SCOPE[group].keys()))
    elif len(SCOPE[group].keys()) ==  1:
        sub_group = list(SCOPE[group].keys())[0]
    else:
        sub_group = None

    field = faker.catch_phrase()



    nature = random.choice(NATURE)
    operations = random.choice(OPERATIONS)
    description = faker.sentence()
    return {"group": group, "sub_group": sub_group, "field": field, \
            "nature": nature, "operations": operations, "description": description
            }
