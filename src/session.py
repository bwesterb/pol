""" A session is a helper object to manage multiple opened containers. """

class Session(object):
    """ Session is a helper object to keep track of opened containers
        in a safe. """
    def __init__(self, safe):
        self.safe = safe
        self.containers = list()
        self._container_set = set()

    def unlock(self, password):
        """ Open containers with the given password or increases access
            to an already openend container. """
        # NOTE safe.open_containers will add access to already opened
        #      containers.
        for cnt in self.safe.open_containers(password):
            self._add_container(cnt)

    def _add_container(self, container):
        if container.id in self._container_set:
            return
        self._container_set.add(container.id)
        self.containers.append(container)
