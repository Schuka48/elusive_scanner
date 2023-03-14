class Route:
    def __init__(self, num_of_nodes: int):
        self.nodes = []
        self.num_of_nodes = num_of_nodes

    def shuffle(self):
        pass

    def __str__(self):
        pass

    def get_destination(self) -> str:
        pass


class RouteMaster:
    def __init__(self):
        self.num_of_nodes: int = self.get_num_of_nodes()

    def get_num_of_nodes(self) -> int:
        pass

    def create_route(self) -> Route:
        packet_route = Route(self.num_of_nodes)
        packet_route.shuffle()

        return packet_route

