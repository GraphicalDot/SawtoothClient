



import boto3
import json
import hashlib
from datetime import datetime, timedelta
import asyncio
import random
def generate_s3_key(user_id, file_name):
    if user_id:
        return hashlib.sha3_224(user_id.encode()+ file_name.encode()).hexdigest()
    else:
        return hashlib.sha3_224(str(random.randint(1, 2**10)).encode()+ file_name.encode()).hexdigest()



def store_s3(app_config, key, user_id, data):
        ##TODO : put user_id, file_name
        s3 = boto3.client('s3',
            aws_access_key_id=app_config.STORAGE["AWS_ACCESS_KEY"],
            aws_secret_access_key=app_config.STORAGE["AWS_SECRET_KEY"],
            config= boto3.session.Config(signature_version='s3v4'),
            region_name=app_config.STORAGE["AWS_REGION_NAME"])


        if user_id:
            s3.put_object(Bucket=app_config.STORAGE["BUCKET_NAME"],
                                    Key=key,
                                   Body=data,
                                   Metadata={'user_id': user_id})
        else:
            s3.put_object(Bucket=app_config.STORAGE["BUCKET_NAME"],
                        Key=key,
                       Body=data)


        s3.put_object_acl(Bucket=app_config.STORAGE["BUCKET_NAME"],
                                Key=key, ACL="public-read")
        #key.set_metadata('Content-Type', 'image/jpeg')


        s3.put_object_tagging(Bucket=app_config.STORAGE["BUCKET_NAME"], Key=key,\
                    Tagging=app_config.STORAGE["S3_OBJECT_TAGS"])

        expires = datetime.utcnow() + timedelta(days=(25 * 365))

        #url = s3.generate_presigned_url('get_object', Params = {'Bucket': request.app.config.BUCKET_NAME, 'Key': key}, ExpiresIn =expires.strftime("%s"))
        return f"https://s3.{app_config.STORAGE['AWS_REGION_NAME']}.amazonaws.com/{app_config.STORAGE['BUCKET_NAME']}/{key}"




async def s3_upload(request, filename, encrypted_filebytes):
    hash_filename = file_hash(filename)

    key = '{}/{}'.format(request.app.config.USERS_BUCKET_FOLDER, hash_filename)


    session = aiobotocore.get_session()
    async with session.create_client('s3', region_name=request.app.config.S3_REGION_NAME,
                                   aws_secret_access_key=request.app.config.AWS_SECRET_ACCESS_KEY,
                                   aws_access_key_id=request.app.config.AWS_ACCESS_KEY_ID) as client:
        # upload object to amazon s3
        resp = await client.put_object(Bucket=bucket,
                                            Key=key,
                                            Body=encrypted_filebytes)
        print(resp)

        # getting s3 object properties of file we just uploaded
        resp = await client.get_object_acl(Bucket=bucket, Key=key)
        print(resp)

        # get object from s3
        response = await client.get_object(Bucket=bucket, Key=key)
        # this will ensure the connection is correctly re-used/closed
        async with response['Body'] as stream:
            assert await stream.read() == data

        # list s3 objects using paginator
        paginator = client.get_paginator('list_objects')
        async for result in paginator.paginate(Bucket=bucket, Prefix=folder):
            for c in result.get('Contents', []):
                print(c)

        # delete object from s3
        #resp = await client.delete_object(Bucket=bucket, Key=key)
        #print(resp)
        return
