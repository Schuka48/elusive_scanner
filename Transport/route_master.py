import random
from DB.ip_db import IPDatabase
from Exceptions.exception import RouteError


class Route:
    def __init__(self, nodes: list):
        self.nodes = nodes

        if len(self.nodes) == 0:
            raise RouteError('Route does not contain any node')

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

    def get_destination(self) -> str:
        return self.nodes[-1]


class RouteMaster:
    def __init__(self):
        self.db: IPDatabase = IPDatabase()
        self.num_of_nodes: int = self.get_num_of_nodes()

    def get_num_of_nodes(self) -> int:
        return len(self.db.get_ips())

    def create_route(self, len_of_route: int) -> Route:
        if len_of_route < 1:
            raise RouteError

        if len_of_route > self.num_of_nodes:
            len_of_route = self.num_of_nodes

        node_list: list = self.db.get_ips()[:len_of_route]

        packet_route: Route = Route(node_list)

        return packet_route
