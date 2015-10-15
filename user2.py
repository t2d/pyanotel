from twisted.internet import reactor, stdio
from user import User, IO
import constants

user = User(constants.user2_id, constants.user2_secret)
stdio.StandardIO(IO(user))

reactor.run()
