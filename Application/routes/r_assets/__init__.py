from sanic import Blueprint

from .assets import CREATE_ASSETS_BP
ASSETS_BP = Blueprint.group(CREATE_ASSETS_BP, url_prefix='/assets')
