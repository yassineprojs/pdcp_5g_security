# Implement Timer Management
import threading

class PDCPTimers:
    def __init__(self):
        self.t_reordering = None
        self.discard_timer = None

    def start_t_reordering(self, duration, callback):
        # Start t-Reordering timer
        pass

    def start_discard_timer(self, duration, callback):
        # Start discardTimer
        pass

    def stop_timer(self, timer_name):
        # Stop specified timer
        pass