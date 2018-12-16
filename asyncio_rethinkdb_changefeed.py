import rethinkdb as r
import asyncio
from typing import Callable, Dict


r.set_loop_type('asyncio')

async def get_connection():
    return await r.connect(
        db='test',
        host='localhost'
    )

async def set_change_handler(table_name: str, handler: Callable) -> None:
    print('Listening for changes on {}'.format(table_name))
    connection = await get_connection()
    feed = await r.table(table_name).changes().run(connection)
    while (await feed.fetch_next()):
        change = await feed.next()
        handler(change)
        print('Got a change on table: {}; {}'.format(table_name, change))


def get_handler_map():
    # add any table_name: handler_func here
    return {
        'events': print,
        'actions_status': print,
        'triggers_status': print
    }


def main():
    loop = asyncio.get_event_loop()
    for table_name, handler in get_handler_map().items():
        loop.create_task(set_change_handler(table_name, handler))

    loop.run_forever()

if __name__ == '__main__':
	main()
