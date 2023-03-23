import random
from DB.ip_db import IPDatabase
from Exceptions.exception import RouteError


class Route:
    def __init__(self, nodes: list):
        self.nodes = nodes
        self.__destination = ''

        if len(self.nodes) == 0:
            raise RouteError('Route does not contain any node')

    def set_destination(self, ip_addr: str):
        self.__destination = ip_addr

    def shuffle(self) -> None:
        random.shuffle(self.nodes)

    def __str__(self) -> str:
        return '-'.join(self.nodes)

    @property
    def route(self) -> str:
        self.shuffle()
        return str(self)

    @staticmethod
    def get_route_list(route: str) -> list[str]:
        return route.split('-')

    def get_next_node(self):
        try:
            return self.nodes.pop(0)
        except IndexError:
            return None

    @property
    def last_node(self):
        return self.nodes[-1]

    @property
    def destination(self) -> str:
        return self.__destination

    @property
    def route_length(self):
        return len(self.nodes)

    @property
    def next_addr(self):
        return self.nodes[0]


class RouteMaster:
    def __init__(self, route_len: int):
        self.db: IPDatabase = IPDatabase()
        self.num_of_nodes: int = route_len

    def get_num_of_nodes(self) -> int:
        return len(self.db.get_ips())

    def create_route(self, len_of_route: int = 1) -> Route:
        if len_of_route < 1:
            raise RouteError

        if len_of_route > self.num_of_nodes:
            len_of_route = self.num_of_nodes

        node_list: list[tuple[str]] = self.db.get_ips()

        route_list = []

        for i in range(0, len_of_route):
            node = random.choice(node_list)
            route_list.append(node[0])
            node_list.remove(node)

        packet_route: Route = Route(route_list)

        return packet_route
