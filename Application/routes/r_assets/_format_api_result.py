


def format_get_assets(assets):

    [[data.pop(field) for field in ["master_key",
                            "master_url",
                            "time", "idx", "public"] if data.get(field)]
                    for data in assets]

    if assets:
        headers = assets[0].keys()
    else:
        headers = None

    return headers, assets
