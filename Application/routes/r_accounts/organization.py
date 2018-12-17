

from .authorization import authorized

from sanic import Blueprint
ACCOUNT_ORG_BP = Blueprint('organization', url_prefix='/')


@ACCOUNT_ORG_BP.get('organization_account')
@authorized()
async def get_organization_account(request, requester):
    """
    To get all the account created by the requester
    """
    if requester["role"] == "CHILD":

        org_address = addresser.child_account_address(
                    requester["public"], 0)

        org_account = await deserialize_state.deserialize_child(
                    request.app.config.REST_API_URL, org_address)

    else:

        org_address = addresser.create_organization_account_address(
            requester["acc_zero_pub"], 0)

        org_account = await deserialize_state.deserialize_org_account(
            request.app.config.REST_API_URL, org_address)


    headers, data = format_get_organization_account(org_account)
    if org_account:

        return response.json(
            {
            'error': False,
            'success': True,
            'message': "Orgnization account found",
            "data": data,
            "headers": headers
            })
    else:
        raise CustomError("No orgnization account can be found for this user")



@ACCOUNT_ORG_BP.post('organization_account')
@authorized()
async def create_organization_account(request, requester):
    #This creates a float_account transaction which user has to claim later
    #to perform any action on the blockchain
    #Create a organization float account on the the blockchain and store details on the
    #database, Requester role will be checked whether it is allowed to create
    #an organizaion of the desired role or not

    #Child account will not have a float account as we already have a
    #gurantee from the orgnisation that it is a valid account,

    #If its not, Its the responsibility of the orgnization

    #role could be anything like MASTER

    #gst_number and tan_number are optional at this stage,
    #later when claiming the account pancard of the user must be matched
    #with the details of either gst or tan
    required_fields = ["org_name", "email", "pancard",
             "role", "phone_number"]


    validate_fields(required_fields, request.json)
    if requester["role"] == "CHILD":
        role_to_be_checked = requester["parent_role"]
    else:
        role_to_be_checked = requester["role"]

    logging.info(f"This is the role to be checked {role_to_be_checked}")

    if role_to_be_checked not in request.app.config.ALLOWED_ROLES:
        raise Exception(f"Unknown role, '{request.json['user_role']}' ROLE is not defined")

    if request.json["role"] not in request.app.config.ROLES[role_to_be_checked]:
        raise errors.AccountCreationError(
                message=f"The user with user_id {requester['user_id']} is not\
                allowed to create ROLE={request.json['role']}")

    pending_org = await accounts_db.find_pending_account(request.app,
                            request.json["pancard"], request.json["email"])

    if pending_org:
        raise errors.PendingAccountError("Organization accounts already exists")


    ##TODO: SOmehow check whether the same orgnization name has same pancard and email
    ##from some third party government API
    org = await accounts_db.find_account(request.app,
                            request.json["org_name"],
                            request.json["pancard"], request.json["email"])

    if org:
        raise errors.AccountError("Organization account already exists")


    ##Tis implies that the user who wanted to create user_role doesnt
    ##have the permission to do so.


    new_user = await new_account(request.app, request.json["pancard"],
                    request.json["phone_number"], request.json["email"],
                    request.json["role"], request.get("gst_number"),
                    request.get("tan_number"), request.json["org_name"])

    logging.info(f"New user data is {new_user}")

    new_user = await submit_float_account(request.app, requester, new_user)

    #A new asset will be created after generating a random index keys from the
    ##new_user, The transaction will be signed by this random index public key,
    ##after the successful submission the user data must be submitted
    #check if the user has role "ADMIN stored in the database"

    ##if organization_name exists in the DB, reject
    ##implies that organization_name is already registered on the blockchain

    ##now submit a float transaction with the data, which will be claimed later
    ##by the user after verification of their email id and adhaar

    return response.json(
        {
            'error': False,
            'success': True,
            'message': "Float Account has been created",
            'data': {"user": new_user}
        })
