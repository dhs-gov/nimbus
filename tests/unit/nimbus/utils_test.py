import unittest

from nimbus.utils import merged_dicts

class MergedDictsTest(unittest.TestCase):

    CASES = [
        ({}, {}, {}),
        ({'a': 1, 'b': 2}, {'a': 1}, {'b': 2}),
        ({'a': 'right'}, {'a': 'left'}, {'a': 'right'}),
        ({'a': 'right'}, {'a': {'nested': 'left'}}, {'a': 'right'}),
        ({'nested': {'a': 1, 'b': 2, 'override': 'right'}},
         {'nested': {'a': 1, 'override': 'left'}},
         {'nested': {'b': 2, 'override': 'right'}}),
    ]

    def test_merge(self):
        for expected_result, lhs, rhs in self.CASES:
            print 'expecting', expected_result, lhs, rhs
            result = merged_dicts(lhs, rhs)
            self.assertEquals(result, expected_result)

