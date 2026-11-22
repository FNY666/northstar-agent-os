import time
import unittest
from countdown import Countdown

class CountdownTests(unittest.TestCase):
    def test_deadline(self):
        timer = Countdown(0.001)
        time.sleep(0.02)
        self.assertTrue(timer.expired())

if __name__ == "__main__":
    unittest.main()
