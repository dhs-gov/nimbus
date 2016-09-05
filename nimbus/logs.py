"""
Default log tools for nimbus.
"""

import logging
import sys

log = logging.getLogger('nimbus')
log.setLevel(logging.INFO)

logging.basicConfig(
        format='%(asctime)s %(name)s: %(levelname)s %(message)s',
        stream=sys.stderr
)

def set_log_quiet_mode():
    log.setLevel(logging.WARNING)

def set_log_debug_mode():
    #logging.getLogger().setLevel(logging.INFO)
    log.setLevel(logging.DEBUG)
