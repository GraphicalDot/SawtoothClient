

def format_get_organization_account(data):
    [ data.pop(field) for field in  ["float_account_idxs",
                            "child_account_idxs",
                            "receive_asset_idxs",
                            "share_asset_idxs",
                            "create_asset_idxs",
                            "indian_time", "time"] if data.get(field)]


    headers = data.keys()

    return headers, data



def format_get_children(children):
    [[data.pop(field) for field in  ["float_account_idxs",
                            "child_account_idxs",
                            "receive_asset_idxs",
                            "share_asset_idxs",
                            "create_asset_idxs",
                            "indian_time", "time",
                            "parent_zero_pub",
                            "signed_nonce",
                            "nonce_hash",
                            "public", "nonce", "parent_role"] if data.get(field)]
                    for data in children]


    if children:
        headers = children[0].keys()
    else:
        headers = None
    return headers, children


def format_get_float_accounts(float_accounts):
    [[data.pop(field) for field in  [
                            "create_asset_idxs",
                            "indian_time", "time",
                            "parent_zero_pub",
                            "signed_nonce",
                            "nonce_hash",
                            "public", "nonce", "parent_role"] if data.get(field)]
                    for data in float_accounts]


    if float_accounts:
        headers = float_accounts[0].keys()
    else:
        headers = None

    return headers, float_accounts
